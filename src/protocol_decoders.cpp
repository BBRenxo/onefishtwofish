#include "protocol_decoders.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace eac {

namespace {

std::string bytes_to_hex(std::span<const uint8_t> bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<unsigned>(b);
    }
    return oss.str();
}

std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

} // namespace

// Exact translation of EasyAntiCheat_EOS.exe (v1.5.9) VA 0x0042499a..0x00424a0d
void eos_bin_rolling_decrypt(std::span<uint8_t> buf) {
    const size_t n = buf.size();
    if (n <= 1) {
        return;
    }

    // 0x0042499f..0x004249ae:
    // lea ecx, [edx + edx*2]; neg ecx; add cl, [eax+edx+0x1b]; add cl, 3; mov [eax+edx+0x1b], cl
    const uint8_t tail_delta = static_cast<uint8_t>(-3 * static_cast<int32_t>(n));
    buf[n - 1] = static_cast<uint8_t>(buf[n - 1] + tail_delta + 3U);

    if (n == 2) {
        // 0x004249b7 -> 0x00424a06
        buf[0] = static_cast<uint8_t>(buf[0] - buf[1]);
        return;
    }

    size_t ecx = n - 2;
    // 0x004249bc: test dl, 1; je 0x4249d1
    if ((n & 1U) != 0U) {
        const uint8_t odd_mask = static_cast<uint8_t>(
            static_cast<uint8_t>(-3 * static_cast<int32_t>(ecx)) - buf[n - 1]);
        buf[n - 2] = static_cast<uint8_t>(buf[n - 2] + odd_mask);
        ecx = n - 3;
    }

    // 0x004249d1: cmp edx, 3; je 0x424a06
    if (n > 3) {
        uint8_t dl = static_cast<uint8_t>(-3 * static_cast<int32_t>(ecx));
        while (ecx != 0) {
            const uint8_t bl = static_cast<uint8_t>(buf[ecx] - buf[ecx + 1] + dl);
            buf[ecx] = bl;
            const uint8_t bh = static_cast<uint8_t>(dl - bl + buf[ecx - 1] + 3U);
            buf[ecx - 1] = bh;
            dl = static_cast<uint8_t>(dl + 6U);
            ecx -= 2;
        }
    }

    // 0x00424a06..0x00424a0a: sub byte ptr [eax+0x1c], [eax+0x1d]
    buf[0] = static_cast<uint8_t>(buf[0] - buf[1]);
}

// Exact algebraic inverse of eos_bin_rolling_decrypt
void eos_bin_rolling_encrypt(std::span<uint8_t> buf) {
    const size_t n = buf.size();
    if (n <= 1) {
        return;
    }

    // 1. Invert final step: buf[0] -= buf[1]
    buf[0] = static_cast<uint8_t>(buf[0] + buf[1]);

    // 2. Invert even-index backward pair loop in forward ascending order (ecx = 2, 4, ..., start_even)
    if (n > 3) {
        const size_t start_even = ((n & 1U) != 0U) ? (n - 3) : (n - 2);
        for (size_t ecx = 2; ecx <= start_even; ecx += 2) {
            const uint8_t dl = static_cast<uint8_t>(-3 * static_cast<int32_t>(ecx));
            const uint8_t bl = buf[ecx];
            buf[ecx - 1] = static_cast<uint8_t>(buf[ecx - 1] - dl + bl - 3U);
            buf[ecx] = static_cast<uint8_t>(bl + buf[ecx + 1] - dl);
        }
    }

    // 3. Invert odd-length tail adjustment
    if (n >= 3 && ((n & 1U) != 0U)) {
        const size_t c = n - 2;
        const uint8_t odd_mask = static_cast<uint8_t>(
            static_cast<uint8_t>(-3 * static_cast<int32_t>(c)) - buf[n - 1]);
        buf[n - 2] = static_cast<uint8_t>(buf[n - 2] - odd_mask);
    }

    // 4. Invert initial tail-byte adjustment
    const uint8_t tail_delta = static_cast<uint8_t>(-3 * static_cast<int32_t>(n));
    buf[n - 1] = static_cast<uint8_t>(buf[n - 1] - tail_delta - 3U);
}

CipherSelfTestResult run_rolling_cipher_selftest() {
    constexpr std::array<size_t, 11> kSizes = {0, 1, 2, 3, 4, 5, 15, 16, 64, 257, 4096};
    CipherSelfTestResult res{};
    res.tested_sizes = kSizes.size();

    for (size_t sz : kSizes) {
        std::vector<uint8_t> orig(sz);
        uint64_t prng = 0x9E3779B97F4A7C15ULL ^ (sz * 0xBF58476D1CE4E5B9ULL);
        for (size_t i = 0; i < sz; ++i) {
            prng ^= prng >> 12;
            prng ^= prng << 25;
            prng ^= prng >> 27;
            orig[i] = static_cast<uint8_t>((prng * 0x2545F4914F6CDD1DULL) >> 56);
        }

        std::vector<uint8_t> work = orig;
        eos_bin_rolling_encrypt(work);
        if (sz >= 2 && work == orig) {
            res.passed = false;
            res.detail = "Encryption produced unmutated buffer at size=" + std::to_string(sz);
            return res;
        }
        eos_bin_rolling_decrypt(work);
        if (work != orig) {
            res.passed = false;
            res.detail = "Round-trip mismatch at size=" + std::to_string(sz);
            return res;
        }
    }

    res.passed = true;
    res.detail = "Bit-exact round-trip verified across 11 buffer sizes (0..4096, odd & even)";
    return res;
}

uint64_t derive_prologue_kstate(uint64_t caller_seed, uint64_t c_mix) noexcept {
    const uint64_t t = caller_seed * c_mix;
    const uint64_t shift_amt = (t >> 60) & 0x3FULL;
    const uint64_t folded = (t >> 32) >> shift_amt;
    return ((t ^ folded) * c_mix) ^ caller_seed;
}

uint64_t decrypt_affine_pointer(uint64_t enc_slot_val, uint64_t c_mul, uint64_t k_state) noexcept {
    return enc_slot_val - (c_mul * k_state);
}

CatalogBaseBinInfo parse_base_bin_catalog(const std::string& path) {
    CatalogBaseBinInfo info{};
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return info;
    }
    const auto end_pos = ifs.tellg();
    if (end_pos <= 0) {
        return info;
    }
    std::vector<uint8_t> data(static_cast<size_t>(end_pos));
    ifs.seekg(0, std::ios::beg);
    if (!ifs.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()))) {
        return info;
    }

    info.total_size = data.size();
    info.sha256 = compute_sha256_hex(data);
    const size_t hdr_len = std::min<size_t>(32, data.size());
    info.header_hex = bytes_to_hex(std::span<const uint8_t>(data.data(), hdr_len));

    if (data.size() >= 8 &&
        data[0] == 0x45 && data[1] == 0x41 && data[2] == 0x43 && data[3] == 0x00) {
        info.valid_magic = true;
        info.version = static_cast<uint32_t>(data[4]) |
                       (static_cast<uint32_t>(data[5]) << 8) |
                       (static_cast<uint32_t>(data[6]) << 16) |
                       (static_cast<uint32_t>(data[7]) << 24);
    }

    std::string cur;
    for (uint8_t ch : data) {
        if (ch >= 32 && ch < 127) {
            cur.push_back(static_cast<char>(ch));
        } else {
            if (cur.size() >= 6 && info.extracted_strings.size() < 24) {
                info.extracted_strings.push_back(cur);
            }
            cur.clear();
        }
    }
    if (cur.size() >= 6 && info.extracted_strings.size() < 24) {
        info.extracted_strings.push_back(cur);
    }

    return info;
}

EosSdkAntiCheatReport analyze_eossdk_exports(const PeImage& eossdk_pe) {
    EosSdkAntiCheatReport rep{};
    const auto exports = eossdk_pe.parse_exports();
    for (const auto& exp : exports) {
        if (exp.name.rfind("EOS_AntiCheatClient_", 0) == 0) {
            rep.client_exports.push_back(exp);
        } else if (exp.name.rfind("EOS_AntiCheatServer_", 0) == 0) {
            rep.server_exports.push_back(exp);
        }
    }

    auto by_rva = [](const ExportEntry& a, const ExportEntry& b) {
        return a.rva < b.rva;
    };
    std::sort(rep.client_exports.begin(), rep.client_exports.end(), by_rva);
    std::sort(rep.server_exports.begin(), rep.server_exports.end(), by_rva);

    rep.client_export_count = rep.client_exports.size();
    rep.server_export_count = rep.server_exports.size();
    return rep;
}

std::string format_protocol_markdown(
    const CipherSelfTestResult& cipher_test,
    const CatalogBaseBinInfo& catalog_info,
    const EosSdkAntiCheatReport& eossdk_report,
    const PeImage* service_v159,
    const PeImage* service_v153_bak) {
    (void)eossdk_report;
    std::ostringstream md;
    md << "## Protocol, Cipher, Catalog & EOSSDK Verification\n\n";

    md << "### 1. `Global\\EasyAntiCheat_EOSBin` Rolling Byte-Cipher (`0x0042499a..0x00424a0d`)\n";
    md << "- **Self-Test Status**: `" << (cipher_test.passed ? "PASS" : "FAIL") << "`\n";
    md << "- **Sizes Verified**: `" << cipher_test.tested_sizes << "` (`" << cipher_test.detail << "`)\n\n";

    md << "### 2. Signed Integrity Catalog (`Certificates/base.bin`)\n";
    md << "- **Header Magic Valid (`\"EAC\\0\"`)**: `" << (catalog_info.valid_magic ? "true" : "false") << "`\n";
    md << "- **Catalog Version**: `" << catalog_info.version << "`\n";
    md << "- **Size**: `" << catalog_info.total_size << "` bytes\n";
    md << "- **SHA-256**: `" << catalog_info.sha256 << "`\n";
    md << "- **Header (32 bytes)**: `" << catalog_info.header_hex << "`\n\n";

    if (service_v159 != nullptr && service_v153_bak != nullptr) {
        auto count_by_dll = [](const PeImage& pe) {
            std::map<std::string, size_t> counts;
            for (const auto& imp : pe.parse_standard_imports()) {
                counts[to_lower_ascii(imp.dll_name)]++;
            }
            return counts;
        };
        const auto imps_159 = count_by_dll(*service_v159);
        const auto imps_153 = count_by_dll(*service_v153_bak);
        auto get_cnt = [](const std::map<std::string, size_t>& m, const std::string& k) -> size_t {
            auto it = m.find(k);
            return (it != m.end()) ? it->second : 0;
        };

        md << "### 3. Service Binary Evolution (`EasyAntiCheat_EOS.exe` v1.5.9 vs v1.5.3 `.bak`)\n\n";
        md << "| Metric | `v1.5.9` (Live) | `v1.5.3` (`.bak`) |\n";
        md << "|---|---|---|\n";
        md << "| File Size (Bytes) | `" << service_v159->raw_bytes().size() << "` | `" << service_v153_bak->raw_bytes().size() << "` |\n";
        md << "| SHA-256 | `" << service_v159->sha256_hex() << "` | `" << service_v153_bak->sha256_hex() << "` |\n";
        md << "| `EntryRVA` / `SizeOfImage` | `0x" << std::hex << service_v159->entry_rva() << "` / `0x" << service_v159->size_of_image()
           << "` | `0x" << service_v153_bak->entry_rva() << "` / `0x" << service_v153_bak->size_of_image() << std::dec << "` |\n";
        md << "| Section Count | `" << service_v159->sections().size() << "` (`.tls` present) | `" << service_v153_bak->sections().size() << "` |\n";
        md << "| `tbs.dll` / `ncrypt.dll` Imports | `" << get_cnt(imps_159, "tbs.dll") << "` / `" << get_cnt(imps_159, "ncrypt.dll")
           << "` | `" << get_cnt(imps_153, "tbs.dll") << "` / `" << get_cnt(imps_153, "ncrypt.dll") << "` |\n";
        md << "| `ws2_32.dll` / `crypt32.dll` Imports | `" << get_cnt(imps_159, "ws2_32.dll") << "` / `" << get_cnt(imps_159, "crypt32.dll")
           << "` | `" << get_cnt(imps_153, "ws2_32.dll") << "` / `" << get_cnt(imps_153, "crypt32.dll") << "` |\n\n";
    }

    md << "### 4. `EOSSDK-Win64-Shipping.dll` Anti-Cheat Exports (`"
       << eossdk_report.client_export_count << "` Client, `"
       << eossdk_report.server_export_count << "` Server)\n\n";
    md << "| Export Name | Ordinal | RVA |\n";
    md << "|---|---|---|\n";
    for (const auto& exp : eossdk_report.client_exports) {
        md << "| `" << exp.name << "` | `" << exp.ordinal << "` | `0x"
           << std::hex << std::setw(7) << std::setfill('0') << exp.rva << std::dec << "` |\n";
    }
    md << "\n";
    return md.str();
}

} // namespace eac
