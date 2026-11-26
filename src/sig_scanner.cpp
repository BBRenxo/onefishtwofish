#include "sig_scanner.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <map>
#include <sstream>

namespace eac {

namespace {

struct PatternToken {
    uint8_t value = 0;
    bool wildcard = false;
};

int hex_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

std::vector<PatternToken> parse_ida_pattern(std::string_view pat) {
    std::vector<PatternToken> out;
    size_t i = 0;
    while (i < pat.size()) {
        while (i < pat.size() && std::isspace(static_cast<unsigned char>(pat[i]))) {
            ++i;
        }
        if (i >= pat.size()) {
            break;
        }
        size_t j = i;
        while (j < pat.size() && !std::isspace(static_cast<unsigned char>(pat[j]))) {
            ++j;
        }
        const std::string_view tok = pat.substr(i, j - i);
        i = j;
        if (tok == "?" || tok == "??") {
            out.push_back(PatternToken{0, true});
            continue;
        }
        if (tok.size() == 2) {
            const int hi = hex_nibble(tok[0]);
            const int lo = hex_nibble(tok[1]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(PatternToken{static_cast<uint8_t>((hi << 4) | lo), false});
            }
        }
    }
    return out;
}

inline uint32_t read_u32_le(const uint8_t* p) noexcept {
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

inline int32_t read_i32_le(const uint8_t* p) noexcept {
    int32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

inline uint64_t read_u64_le(const uint8_t* p) noexcept {
    uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

std::string bytes_to_hex(std::span<const uint8_t> sp, size_t max_len = 16) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    const size_t n = std::min(sp.size(), max_len);
    for (size_t i = 0; i < n; ++i) {
        if (i > 0) oss << ' ';
        oss << std::setw(2) << static_cast<unsigned>(sp[i]);
    }
    return oss.str();
}

std::string format_sec_label(const SectionInfo& sec, size_t idx) {
    if (!sec.name.empty()) {
        return sec.name;
    }
    if (sec.virtual_size >= 0x1000000U) {
        return "Sec[" + std::to_string(idx) + "] (VM/Flat)";
    }
    return "Sec[" + std::to_string(idx) + "]";
}

std::string kuser_field_name(uint32_t off) {
    switch (off) {
        case 0x000: return "TickCountLowDeprecated";
        case 0x004: return "TickCountMultiplier";
        case 0x008: return "InterruptTime";
        case 0x014: return "SystemTime";
        case 0x020: return "TimeZoneBias";
        case 0x02C: return "ImageNumberLow";
        case 0x030: return "NtSystemRoot";
        case 0x260: return "NtBuildNumber";
        case 0x264: return "NtProductType";
        case 0x268: return "ProductTypeIsValid";
        case 0x26C: return "NtMajorVersion";
        case 0x270: return "NtMinorVersion";
        case 0x274: return "ProcessorFeatures[0]";
        case 0x2D0: return "SuiteMask";
        case 0x2D4: return "KdDebuggerEnabled";
        case 0x2D5: return "MitigationPolicies";
        case 0x2D8: return "ActiveConsoleId";
        case 0x2DC: return "DismountCount";
        case 0x2E8: return "NumberOfPhysicalPages";
        case 0x2EC: return "SafeBootMode";
        case 0x2F0: return "SharedDataFlags";
        case 0x320: return "TickCount";
        case 0x330: return "Cookie";
        case 0x338: return "ConsoleSessionForegroundProcessId";
        default: {
            if (off > 0x274 && off < 0x2B4) {
                return "ProcessorFeatures[" + std::to_string(off - 0x274) + "]";
            }
            std::ostringstream oss;
            oss << "Offset_0x" << std::hex << off;
            return oss.str();
        }
    }
}

bool contains_subspan(std::span<const uint8_t> hay, std::span<const uint8_t> needle) noexcept {
    if (needle.empty() || hay.size() < needle.size()) {
        return false;
    }
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        if (std::memcmp(hay.data() + i, needle.data(), needle.size()) == 0) {
            return true;
        }
    }
    return false;
}

} // namespace

std::vector<uint32_t> scan_pattern_rvas(const PeImage& pe, std::string_view ida_pattern, bool executable_only) {
    std::vector<uint32_t> hits;
    const auto tokens = parse_ida_pattern(ida_pattern);
    if (tokens.empty()) {
        return hits;
    }

    const auto raw = pe.raw_bytes();
    const size_t pat_len = tokens.size();

    for (const auto& sec : pe.sections()) {
        if (executable_only && (sec.characteristics & 0x20000000U) == 0) {
            continue;
        }
        if (sec.raw_ptr >= raw.size() || sec.raw_size < pat_len) {
            continue;
        }
        const size_t avail = std::min<size_t>(sec.raw_size, raw.size() - sec.raw_ptr);
        if (avail < pat_len) {
            continue;
        }
        const uint8_t* base = raw.data() + sec.raw_ptr;
        const size_t limit = avail - pat_len;
        for (size_t off = 0; off <= limit; ++off) {
            bool match = true;
            for (size_t k = 0; k < pat_len; ++k) {
                if (!tokens[k].wildcard && base[off + k] != tokens[k].value) {
                    match = false;
                    break;
                }
            }
            if (match) {
                hits.push_back(sec.virtual_address + static_cast<uint32_t>(off));
            }
        }
    }
    return hits;
}

DriverScanSummary scan_kernel_driver(const std::string& label, const PeImage& pe) {
    DriverScanSummary sum;
    sum.label = label;
    sum.path = pe.path();

    const auto raw = pe.raw_bytes();
    const auto& secs = pe.sections();

    size_t total_affine_thunks = 0;

    for (size_t s_idx = 0; s_idx < secs.size(); ++s_idx) {
        const auto& sec = secs[s_idx];
        if (sec.raw_ptr >= raw.size() || sec.raw_size == 0) {
            continue;
        }
        const size_t avail = std::min<size_t>(sec.raw_size, raw.size() - sec.raw_ptr);
        const uint8_t* sdata = raw.data() + sec.raw_ptr;
        const bool is_exec = (sec.characteristics & 0x20000000U) != 0;
        const bool is_text = (sec.name == ".text");
        const bool is_sec7 = is_exec && !is_text && sec.virtual_size >= 0x1000000U;
        const std::string sec_lbl = format_sec_label(sec, s_idx);

        if (sec.name == ".rdata" && avail >= 16) {
            static constexpr uint8_t kRsmbHdr[16] = {
                0x42, 0x4D, 0x53, 0x52, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            for (size_t i = 0; i + 16 <= avail; ++i) {
                if (std::memcmp(sdata + i, kRsmbHdr, 16) == 0) {
                    sum.rsmb_rdata_rvas.push_back(sec.virtual_address + static_cast<uint32_t>(i));
                }
            }
        }

        if (!is_exec) {
            continue;
        }

        // 1. CPUID (0F A2)
        for (size_t i = 0; i + 2 <= avail; ++i) {
            if (sdata[i] == 0x0FU && sdata[i + 1] == 0xA2U) {
                const uint32_t rva = sec.virtual_address + static_cast<uint32_t>(i);
                if (is_text) {
                    sum.cpuid_rvas_text.push_back(rva);
                } else if (is_sec7) {
                    sum.cpuid_rvas_sec7.push_back(rva);
                }
            }
        }

        // 2. KUSER_SHARED_DATA 10-byte movabs reg64, 0xFFFFF78000000xxx
        for (size_t i = 0; i + 10 <= avail; ++i) {
            const uint8_t rex = sdata[i];
            const uint8_t op = sdata[i + 1];
            if ((rex == 0x48U || rex == 0x49U) && (op >= 0xB8U && op <= 0xBFU)) {
                const uint64_t imm = read_u64_le(sdata + i + 2);
                if (imm >= 0xFFFFF78000000000ULL && imm < 0xFFFFF78000001000ULL) {
                    KuserReadHit kh;
                    kh.insn_rva = sec.virtual_address + static_cast<uint32_t>(i);
                    kh.kuser_offset = static_cast<uint32_t>(imm - 0xFFFFF78000000000ULL);
                    kh.section_name = sec_lbl;
                    kh.field_name = kuser_field_name(kh.kuser_offset);
                    kh.reg_code = static_cast<uint8_t>(((rex == 0x49U) ? 8U : 0U) + (op - 0xB8U));
                    sum.kuser_hits.push_back(std::move(kh));
                }
            }
        }

        // 3. IOCTL_STORAGE_QUERY_PROPERTY (0x002D1400) & SMART (0x7C088 / 0x7C084 / +0x7C0 MBA)
        for (size_t i = 0; i + 8 <= avail; ++i) {
            // C7 40..47 disp8 00 14 2D 00 or REX + C7 ...
            if (sdata[i] == 0x00U && sdata[i + 1] == 0x14U && sdata[i + 2] == 0x2DU && sdata[i + 3] == 0x00U) {
                if (i >= 3 && sdata[i - 3] == 0xC7U) {
                    const size_t start = (i >= 4 && (sdata[i - 4] >= 0x40U && sdata[i - 4] <= 0x4FU)) ? (i - 4) : (i - 3);
                    sum.ioctl_storage_2d1400_rvas.push_back(sec.virtual_address + static_cast<uint32_t>(start));
                }
            }
            // SMART_SEND_DRIVE_COMMAND (0x7C084) or SMART_RCV_DRIVE_DATA (0x7C088)
            if ((sdata[i] == 0x84U || sdata[i] == 0x88U) &&
                sdata[i + 1] == 0xC0U && sdata[i + 2] == 0x07U && sdata[i + 3] == 0x00U) {
                if (i >= 3 && sdata[i - 2] == 0x8DU) {
                    sum.smart_7c088_or_7c084_rvas.push_back(sec.virtual_address + static_cast<uint32_t>(i - 3));
                }
            }
            // MBA lea r9d, [r8 + 0x7C0]; and r9d, 0xFFFFFF ((44|45) 8D 88 C0 07 00 00 41 81 E1 FF FF FF 00)
            if (i + 14 <= avail &&
                (sdata[i] == 0x44U || sdata[i] == 0x45U) && sdata[i + 1] == 0x8DU && sdata[i + 2] == 0x88U &&
                sdata[i + 3] == 0xC0U && sdata[i + 4] == 0x07U && sdata[i + 5] == 0x00U && sdata[i + 6] == 0x00U &&
                sdata[i + 7] == 0x41U && sdata[i + 8] == 0x81U && sdata[i + 9] == 0xE1U) {
                sum.smart_7c088_or_7c084_rvas.push_back(sec.virtual_address + static_cast<uint32_t>(i));
            }
        }

        // 4. Per-call affine pointer decryption thunk in .text:
        //    48 B8 <8-byte mul_const>
        //    (48|49) 0F AF (C0..C7)        ; imul rax, reg_state
        //    (48|4C) 8B (05|0D|15|1D|25|2D|35|3D) <disp32> ; mov reg_dst, [rip + disp32]
        //    (48|49) 29 (C0..C7)           ; sub reg_dst, rax
        if (is_text && avail >= 24) {
            for (size_t i = 0; i + 24 <= avail; ++i) {
                if (sdata[i] != 0x48U || sdata[i + 1] != 0xB8U) {
                    continue;
                }
                const uint8_t imul_rex = sdata[i + 10];
                if ((imul_rex != 0x48U && imul_rex != 0x49U) ||
                    sdata[i + 11] != 0x0FU || sdata[i + 12] != 0xAFU ||
                    sdata[i + 13] < 0xC0U || sdata[i + 13] > 0xC7U) {
                    continue;
                }
                const uint8_t mov_rex = sdata[i + 14];
                const uint8_t mov_op = sdata[i + 15];
                const uint8_t mov_modrm = sdata[i + 16];
                if ((mov_rex != 0x48U && mov_rex != 0x4CU) || mov_op != 0x8BU || (mov_modrm & 0xC7U) != 0x05U) {
                    continue;
                }
                const uint8_t sub_rex = sdata[i + 21];
                const uint8_t sub_op = sdata[i + 22];
                const uint8_t sub_modrm = sdata[i + 23];
                if ((sub_rex != 0x48U && sub_rex != 0x49U) || sub_op != 0x29U || (sub_modrm & 0xF8U) != 0xC0U) {
                    continue;
                }

                ++total_affine_thunks;
                if (sum.affine_thunks_sample.size() < 32) {
                    const uint32_t thunk_rva = sec.virtual_address + static_cast<uint32_t>(i);
                    const uint64_t mul_c = read_u64_le(sdata + i + 2);
                    const int32_t disp = read_i32_le(sdata + i + 17);
                    const int64_t slot_rva_signed = static_cast<int64_t>(thunk_rva) + 21LL + disp;
                    uint32_t slot_rva = 0;
                    uint64_t slot_val = 0;
                    if (slot_rva_signed > 0 && slot_rva_signed < static_cast<int64_t>(pe.size_of_image())) {
                        slot_rva = static_cast<uint32_t>(slot_rva_signed);
                        const auto slot_sp = pe.slice_rva(slot_rva, 8);
                        if (slot_sp.size() == 8) {
                            slot_val = read_u64_le(slot_sp.data());
                        }
                    }
                    sum.affine_thunks_sample.push_back(AffineThunkHit{
                        thunk_rva, mul_c, slot_rva, slot_val, sec_lbl
                    });
                }
            }
        }
    }

    // Populate deterministic RvaVerificationChecks
    auto add_check = [&](const std::string& name, uint32_t rva, bool ok, std::span<const uint8_t> obs, const std::string& detail) {
        sum.checks.push_back(RvaVerificationCheck{
            label, name, rva, ok, bytes_to_hex(obs, 13), detail
        });
    };

    // Check 1: EntryPoint RVA readable
    {
        const auto ep = pe.slice_rva(pe.entry_rva(), 16);
        add_check("DriverEntry RVA mapped", pe.entry_rva(), ep.size() == 16, ep,
                  "PE OptionalHeader.AddressOfEntryPoint maps to executable bytes");
    }

    // Check 2: Per-build documented ground-truth RVAs
    struct ExpectedDriverRvas {
        uint32_t rsmb_rva;
        uint32_t mbr_str_rva;
        uint32_t safeboot_rva;
        uint32_t systime_rva;
        uint32_t procfeat_rva;
        uint32_t storage_ioctl_rva; // 0 if obfuscated in Sec[7]
        uint32_t smart_rva;         // 0 if not applicable
    };

    std::map<std::string, ExpectedDriverRvas> expected_map = {
        {"eos_live",   {0x303B74U, 0x31D146U, 0x1D19B7U, 0x0CCA5BU, 0x0EFC8BU, 0x2A57F24U, 0U}},
        {"eac_dumped", {0x2D458CU, 0x3092B6U, 0x21EF4EU, 0x171FE2U, 0x2091C8U, 0x0153995U, 0U}},
        {"eacfn",      {0x2C5C8CU, 0x301B5EU, 0x1CB08CU, 0x04DDE3U, 0x2100DEU, 0x00B90FCU, 0x1CD7A24U}},
        {"eos_prior",  {0x2BE27CU, 0x2EF232U, 0x207DCAU, 0x105CF9U, 0x1B11B9U, 0U,         0x08A3B36U}},
    };

    const auto it = expected_map.find(label);
    if (it != expected_map.end()) {
        const auto& exp = it->second;

        // RSMB template
        static constexpr uint8_t kRsmb8[8] = {0x42, 0x4D, 0x53, 0x52, 0x01, 0x00, 0x00, 0x00};
        const auto rsmb_sp = pe.slice_rva(exp.rsmb_rva, 16);
        const bool rsmb_ok = rsmb_sp.size() >= 8 && std::memcmp(rsmb_sp.data(), kRsmb8, 8) == 0;
        add_check("RSMB .rdata template", exp.rsmb_rva, rsmb_ok, rsmb_sp,
                  "SYSTEM_FIRMWARE_TABLE_INFORMATION ('RSMB', Action=1)");

        // MBR:%08x UTF-16LE
        static constexpr uint8_t kMbrUtf16[16] = {
            0x4D, 0x00, 0x42, 0x00, 0x52, 0x00, 0x3A, 0x00,
            0x25, 0x00, 0x30, 0x00, 0x38, 0x00, 0x78, 0x00
        };
        const auto mbr_sp = pe.slice_rva(exp.mbr_str_rva, 16);
        const bool mbr_ok = mbr_sp.size() == 16 && std::memcmp(mbr_sp.data(), kMbrUtf16, 16) == 0;
        add_check("MBR:%08x UTF-16LE formatter", exp.mbr_str_rva, mbr_ok, mbr_sp,
                  "Disk layout telemetry wide format string in .rdata");

        // KUSER_SHARED_DATA+0x2EC (SafeBootMode)
        static constexpr uint8_t kKuser2EC[8] = {0xEC, 0x02, 0x00, 0x00, 0x80, 0xF7, 0xFF, 0xFF};
        const auto sb_sp = pe.slice_rva(exp.safeboot_rva, 13);
        const bool sb_ok = sb_sp.size() == 13 &&
                           (sb_sp[0] == 0x48U || sb_sp[0] == 0x49U) &&
                           std::memcmp(sb_sp.data() + 2, kKuser2EC, 8) == 0;
        add_check("KUSER_SHARED_DATA+0x2EC (SafeBootMode)", exp.safeboot_rva, sb_ok, sb_sp,
                  "10-byte movabs 0xFFFFF780000002EC + 1-byte SafeBootMode read");

        // KUSER_SHARED_DATA+0x014 (SystemTime)
        static constexpr uint8_t kKuser014[8] = {0x14, 0x00, 0x00, 0x00, 0x80, 0xF7, 0xFF, 0xFF};
        const auto st_sp = pe.slice_rva(exp.systime_rva, 10);
        const bool st_ok = st_sp.size() == 10 &&
                           (st_sp[0] == 0x48U || st_sp[0] == 0x49U) &&
                           std::memcmp(st_sp.data() + 2, kKuser014, 8) == 0;
        add_check("KUSER_SHARED_DATA+0x014 (SystemTime)", exp.systime_rva, st_ok, st_sp,
                  "Exact opcode boundary for KSYSTEM_TIME SystemTime read");

        // KUSER_SHARED_DATA+0x274 (ProcessorFeatures[0])
        static constexpr uint8_t kKuser274[8] = {0x74, 0x02, 0x00, 0x00, 0x80, 0xF7, 0xFF, 0xFF};
        const auto pf_sp = pe.slice_rva(exp.procfeat_rva, 10);
        const bool pf_ok = pf_sp.size() == 10 &&
                           (pf_sp[0] == 0x48U || pf_sp[0] == 0x49U) &&
                           std::memcmp(pf_sp.data() + 2, kKuser274, 8) == 0;
        add_check("KUSER_SHARED_DATA+0x274 (ProcessorFeatures)", exp.procfeat_rva, pf_ok, pf_sp,
                  "Exact opcode boundary for BOOLEAN ProcessorFeatures[64] array base");

        // IOCTL_STORAGE_QUERY_PROPERTY (0x002D1400)
        if (exp.storage_ioctl_rva != 0) {
            static constexpr uint8_t kIoctl2D1400[4] = {0x00, 0x14, 0x2D, 0x00};
            const auto io_sp = pe.slice_rva(exp.storage_ioctl_rva, 10);
            const bool io_ok = contains_subspan(io_sp, kIoctl2D1400);
            add_check("IOCTL_STORAGE_QUERY_PROPERTY (0x2D1400)", exp.storage_ioctl_rva, io_ok, io_sp,
                      "IRP IO_STACK_LOCATION IoControlCode = 0x002D1400 store");
        }

        // SMART handler check
        if (exp.smart_rva != 0) {
            const auto sm_sp = pe.slice_rva(exp.smart_rva, 14);
            static constexpr uint8_t k7C0[4] = {0xC0, 0x07, 0x00, 0x00};
            static constexpr uint8_t k7C084[4] = {0x84, 0xC0, 0x07, 0x00};
            const bool sm_ok = contains_subspan(sm_sp, k7C0) || contains_subspan(sm_sp, k7C084);
            add_check("SMART IOCTL MBA dispatcher", exp.smart_rva, sm_ok, sm_sp,
                      "SMART_RCV_DRIVE_DATA (+0x7C0 MBA) / SMART_SEND_DRIVE_COMMAND (0x7C084)");
        }
    }

    // Check affine thunks discovered in .text
    {
        const uint32_t sample_rva = sum.affine_thunks_sample.empty() ? 0U : sum.affine_thunks_sample.front().thunk_rva;
        const auto th_sp = (sample_rva != 0) ? pe.slice_rva(sample_rva, 14) : std::span<const uint8_t>{};
        add_check("Affine pointer call-thunks in .text", sample_rva, total_affine_thunks > 50, th_sp,
                  "Total .text affine call-thunks matched: " + std::to_string(total_affine_thunks));
    }

    if (label == "eacfn") {
        const auto bear = pe.parse_bearimp_imports();
        add_check(".bearimp reconstructed kernel imports", 0x2935000U, bear.size() >= 119,
                  pe.slice_rva(0x2935000U, 12),
                  "Parsed " + std::to_string(bear.size()) + " imports across FLTMGR.SYS, ntoskrnl.exe, msrpc.sys");
    }

    return sum;
}

std::string format_scan_markdown(const std::vector<DriverScanSummary>& summaries) {
    std::ostringstream md;
    md << "## Kernel Driver Cross-Build Signature & RVA Scan\n\n";
    md << "| Driver | `.text` `cpuid` | `Sec[7]` `cpuid` | `KUSER_SHARED_DATA` `movabs` | `.rdata` `'RSMB'` | `0x2D1400` Stores | `SMART` Sites | Checks Passed |\n";
    md << "|---|---|---|---|---|---|---|---|\n";

    for (const auto& s : summaries) {
        size_t passed = 0;
        for (const auto& c : s.checks) {
            if (c.passed) ++passed;
        }
        std::ostringstream rsmb_s;
        if (s.rsmb_rdata_rvas.empty()) {
            rsmb_s << "none";
        } else {
            for (size_t i = 0; i < s.rsmb_rdata_rvas.size(); ++i) {
                if (i > 0) rsmb_s << ", ";
                rsmb_s << "`0x" << std::hex << std::uppercase << s.rsmb_rdata_rvas[i] << "`";
            }
        }
        md << "| `" << s.label << "` | `" << s.cpuid_rvas_text.size() << "` | `" << s.cpuid_rvas_sec7.size()
           << "` | `" << s.kuser_hits.size() << "` | " << rsmb_s.str()
           << " | `" << s.ioctl_storage_2d1400_rvas.size() << "` | `" << s.smart_7c088_or_7c084_rvas.size()
           << "` | `" << passed << "/" << s.checks.size() << "` |\n";
    }
    md << "\n";

    // KUSER_SHARED_DATA cross-build matrix
    md << "### Verified `KUSER_SHARED_DATA` (`0xFFFFF78000000000`) Reads\n\n";
    md << "| Offset | DDK Struct Field | ";
    for (const auto& s : summaries) {
        md << "`" << s.label << "` RVAs | ";
    }
    md << "\n|---|---|";
    for (size_t i = 0; i < summaries.size(); ++i) {
        md << "---|";
    }
    md << "\n";

    std::map<uint32_t, std::string> all_offsets;
    for (const auto& s : summaries) {
        for (const auto& kh : s.kuser_hits) {
            all_offsets[kh.kuser_offset] = kh.field_name;
        }
    }
    for (const auto& [off, fname] : all_offsets) {
        md << "| `+0x" << std::hex << std::setw(3) << std::setfill('0') << std::uppercase << off << "` | `" << fname << "` | ";
        for (const auto& s : summaries) {
            std::vector<const KuserReadHit*> hits;
            for (const auto& kh : s.kuser_hits) {
                if (kh.kuser_offset == off) hits.push_back(&kh);
            }
            if (hits.empty()) {
                md << "— | ";
            } else {
                for (size_t i = 0; i < hits.size(); ++i) {
                    if (i > 0) md << ", ";
                    md << "`0x" << std::hex << std::uppercase << hits[i]->insn_rva << "`";
                    if (hits[i]->section_name != ".text") {
                        md << " (" << hits[i]->section_name << ")";
                    }
                }
                md << " | ";
            }
        }
        md << "\n";
    }
    md << std::dec << "\n";

    // Detailed check results
    md << "### Ground-Truth Byte Verification Checks\n\n";
    md << "| Driver | Check | RVA | Result | Observed Bytes | Notes |\n";
    md << "|---|---|---|---|---|---|\n";
    for (const auto& s : summaries) {
        for (const auto& c : s.checks) {
            md << "| `" << c.binary_label << "` | " << c.check_name
               << " | `0x" << std::hex << std::uppercase << c.rva << std::dec << "` | "
               << (c.passed ? "PASS" : "FAIL") << " | `" << c.observed_hex << "` | "
               << c.detail << " |\n";
        }
    }
    md << "\n";

    // Sample affine thunks
    md << "### Sample Per-Call Affine Pointer Decryption Thunks (`.text`)\n\n";
    md << "| Driver | Thunk RVA | `C_MUL` (`movabs rax`) | Encrypted Slot RVA | Raw Slot Value (`uint64_t`) |\n";
    md << "|---|---|---|---|---|\n";
    for (const auto& s : summaries) {
        const size_t lim = std::min<size_t>(s.affine_thunks_sample.size(), 6);
        for (size_t i = 0; i < lim; ++i) {
            const auto& t = s.affine_thunks_sample[i];
            md << "| `" << s.label << "` | `0x" << std::hex << std::uppercase << t.thunk_rva
               << "` | `0x" << std::setw(16) << std::setfill('0') << t.mul_const
               << "` | `0x" << std::setw(1) << t.table_slot_rva
               << "` | `0x" << std::setw(16) << std::setfill('0') << t.slot_raw_value << std::dec << "` |\n";
        }
    }
    md << "\n";

    return md.str();
}

} // namespace eac
