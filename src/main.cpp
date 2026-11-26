#include "pe_image.hpp"
#include "protocol_decoders.hpp"
#include "sig_scanner.hpp"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct TargetBinarySpec {
    std::string key;
    std::string display_name;
    std::string path;
    bool is_kernel_driver = false;
};

std::string json_escape(std::string_view sv) {
    std::ostringstream oss;
    for (unsigned char c : sv) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (c < 0x20) {
                    oss << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(c) << std::dec;
                } else {
                    oss << static_cast<char>(c);
                }
                break;
        }
    }
    return oss.str();
}

std::string hex_u32(uint32_t v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << v;
    return oss.str();
}

std::string hex_u64(uint64_t v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << v;
    return oss.str();
}

} // namespace

int main(int argc, char** argv) {
    bool write_reports = false;
    bool help_only = false;
    std::filesystem::path out_dir = R"(C:\Users\Administrator\Desktop\eac_reversal)";

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            help_only = true;
        } else if (arg == "--generate-report" || arg == "--all") {
            write_reports = true;
        } else if (arg == "--out-dir" && i + 1 < argc) {
            out_dir = argv[++i];
            write_reports = true;
        }
    }
    if (argc == 1) {
        write_reports = true;
    }

    if (help_only) {
        std::cout << "Usage: eac_inspector [--inventory] [--verify] [--generate-report] [--out-dir <dir>]\n";
        return 0;
    }

    const std::vector<TargetBinarySpec> specs = {
        {"eos_live",     "EasyAntiCheat_EOS.sys (Live)",      R"(C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys)", true},
        {"eac_dumped",   "eac_dumped.sys (Memory Dump)",      R"(C:\Users\Administrator\Downloads\eac_dumped.sys)", true},
        {"eacfn",        "eacfn.sys (.bearimp Reconstructed)", R"(C:\Users\Administrator\Downloads\eacfn.sys)", true},
        {"eos_prior",    "EasyAntiCheat_EOS.sys (Prior)",     R"(C:\Users\Administrator\Downloads\EasyAntiCheat_EOS.sys)", true},
        {"service_v159", "EasyAntiCheat_EOS.exe (v1.5.9)",    R"(C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe)", false},
        {"service_v153", "EasyAntiCheat_EOS.exe.bak (v1.5.3)", R"(C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe.bak)", false},
        {"launcher_eos", "FortniteClient-Win64-Shipping_EAC_EOS.exe", R"(C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping_EAC_EOS.exe)", false},
        {"eossdk",       "EOSSDK-Win64-Shipping.dll",         R"(C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EOSSDK-Win64-Shipping.dll)", false},
    };

    const std::string base_bin_path = R"(C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EasyAntiCheat\Certificates\base.bin)";

    struct LoadedTarget {
        TargetBinarySpec spec;
        eac::PeImage pe;
        std::string sha256;
        size_t pdata_count = 0;
        std::vector<eac::ImportEntry> std_imports;
        std::vector<eac::ImportEntry> bear_imports;
        std::vector<eac::ExportEntry> exports;
    };

    std::vector<LoadedTarget> loaded;
    loaded.reserve(specs.size());
    std::map<std::string, size_t> key_to_idx;

    bool all_ok = true;

    for (const auto& sp : specs) {
        std::string err;
        auto pe_opt = eac::PeImage::load_from_file(sp.path, &err);
        if (!pe_opt.has_value()) {
            std::cerr << "[FAIL] " << sp.key << ": " << err << "\n";
            all_ok = false;
            continue;
        }
        LoadedTarget lt{sp, std::move(*pe_opt), {}, 0, {}, {}, {}};
        lt.sha256 = lt.pe.sha256_hex();
        lt.pdata_count = lt.pe.parse_pdata().size();
        lt.std_imports = lt.pe.parse_standard_imports();
        lt.bear_imports = lt.pe.parse_bearimp_imports();
        lt.exports = lt.pe.parse_exports();

        key_to_idx[sp.key] = loaded.size();
        std::cout << "[OK] Loaded " << std::left << std::setw(14) << sp.key
                  << " size=" << std::setw(10) << lt.pe.raw_bytes().size()
                  << " base=" << std::setw(18) << hex_u64(lt.pe.image_base())
                  << " entry=" << std::setw(10) << hex_u32(lt.pe.entry_rva())
                  << " sha256=" << lt.sha256.substr(0, 16) << "...\n";
        loaded.push_back(std::move(lt));
    }

    std::vector<eac::DriverScanSummary> driver_scans;
    size_t total_checks = 0;
    size_t passed_checks = 0;

    for (const auto& lt : loaded) {
        if (!lt.spec.is_kernel_driver) {
            continue;
        }
        auto scan = eac::scan_kernel_driver(lt.spec.key, lt.pe);
        for (const auto& chk : scan.checks) {
            ++total_checks;
            if (chk.passed) {
                ++passed_checks;
            } else {
                all_ok = false;
                std::cerr << "[CHECK FAIL] " << chk.binary_label << " | " << chk.check_name
                          << " @ " << hex_u32(chk.rva) << " (" << chk.observed_hex << ")\n";
            }
        }
        driver_scans.push_back(std::move(scan));
    }

    const auto cipher_res = eac::run_rolling_cipher_selftest();
    if (!cipher_res.passed) {
        all_ok = false;
        std::cerr << "[CHECK FAIL] Rolling cipher self-test: " << cipher_res.detail << "\n";
    } else {
        std::cout << "[OK] Rolling cipher self-test passed (" << cipher_res.tested_sizes << " sizes): " << cipher_res.detail << "\n";
    }

    const auto catalog_info = eac::parse_base_bin_catalog(base_bin_path);
    if (!catalog_info.valid_magic) {
        all_ok = false;
        std::cerr << "[CHECK FAIL] base.bin catalog magic check failed: " << base_bin_path << "\n";
    } else {
        std::cout << "[OK] base.bin catalog verified (version=" << catalog_info.version
                  << ", size=" << catalog_info.total_size << ", sha256=" << catalog_info.sha256.substr(0, 16) << "...)\n";
    }

    eac::EosSdkAntiCheatReport eossdk_rep;
    if (const auto it = key_to_idx.find("eossdk"); it != key_to_idx.end()) {
        eossdk_rep = eac::analyze_eossdk_exports(loaded[it->second].pe);
        if (eossdk_rep.client_export_count == 0 || eossdk_rep.server_export_count == 0) {
            all_ok = false;
            std::cerr << "[CHECK FAIL] EOSSDK export count unexpected\n";
        } else {
            std::cout << "[OK] EOSSDK exports verified: client=" << eossdk_rep.client_export_count
                      << ", server=" << eossdk_rep.server_export_count << "\n";
        }
    }

    const eac::PeImage* p_v159 = nullptr;
    const eac::PeImage* p_v153 = nullptr;
    if (const auto it = key_to_idx.find("service_v159"); it != key_to_idx.end()) p_v159 = &loaded[it->second].pe;
    if (const auto it = key_to_idx.find("service_v153"); it != key_to_idx.end()) p_v153 = &loaded[it->second].pe;

    std::cout << "[SUMMARY] Kernel RVA checks: " << passed_checks << "/" << total_checks
              << " | Overall status: " << (all_ok ? "PASS" : "FAIL") << "\n";

    if (write_reports) {
        std::filesystem::create_directories(out_dir);

        // 1. Write VERIFICATION_REPORT.md
        std::ostringstream md;
        md << "# Automated C++20 Ground-Truth Verification Report (`eac_inspector`)\n\n";
        md << "- **Overall Verification Status**: `" << (all_ok ? "PASS (Exit 0)" : "FAIL") << "`\n";
        md << "- **Kernel RVA & Opcode Assertions Passed**: `" << passed_checks << " / " << total_checks << "`\n";
        md << "- **Rolling Cipher Algebraic Round-Trip Self-Test**: `" << (cipher_res.passed ? "PASS" : "FAIL")
           << "` (`" << cipher_res.tested_sizes << "` payload sizes)\n";
        md << "- **Signed Integrity Catalog (`base.bin`)**: `" << (catalog_info.valid_magic ? "VALID" : "INVALID")
           << "` (`v" << catalog_info.version << "`, `" << catalog_info.total_size << "` B, SHA-256 `" << catalog_info.sha256 << "`)\n\n";

        md << "## 1. Measured PE32 / PE32+ Binary Inventory\n\n";
        md << "| Key | Arch | Size (Bytes) | `ImageBase` | `SizeOfImage` | `EntryRVA` | `TimeDateStamp` | `.pdata` | Imports (`.bearimp`) | Exports | SHA-256 |\n";
        md << "|---|---|---|---|---|---|---|---|---|---|---|\n";
        for (const auto& lt : loaded) {
            md << "| `" << lt.spec.key << "` | `" << (lt.pe.is_pe64() ? "x86_64" : "x86")
               << "` | `" << lt.pe.raw_bytes().size()
               << "` | `" << hex_u64(lt.pe.image_base())
               << "` | `" << hex_u32(lt.pe.size_of_image())
               << "` | `" << hex_u32(lt.pe.entry_rva())
               << "` | `" << hex_u32(lt.pe.time_date_stamp())
               << "` | `" << lt.pdata_count
               << "` | `" << lt.std_imports.size();
            if (!lt.bear_imports.empty()) {
                md << " (" << lt.bear_imports.size() << ")";
            }
            md << "` | `" << lt.exports.size()
               << "` | `" << lt.sha256 << "` |\n";
        }
        md << "\n";

        md << "## 2. Section Table Breakdown Across Analyzed Images\n\n";
        for (const auto& lt : loaded) {
            md << "### `" << lt.spec.key << "` (`" << lt.spec.path << "`)\n\n";
            md << "| Index | Name | `VirtualAddress` | `VirtualSize` | `RawPtr` | `RawSize` | `Characteristics` |\n";
            md << "|---|---|---|---|---|---|---|\n";
            const auto& secs = lt.pe.sections();
            for (size_t i = 0; i < secs.size(); ++i) {
                const auto& s = secs[i];
                md << "| `" << i << "` | `" << (s.name.empty() ? "(unnamed)" : s.name)
                   << "` | `" << hex_u32(s.virtual_address)
                   << "` | `" << hex_u32(s.virtual_size)
                   << "` | `" << hex_u32(s.raw_ptr)
                   << "` | `" << hex_u32(s.raw_size)
                   << "` | `" << hex_u32(s.characteristics) << "` |\n";
            }
            md << "\n";
        }

        if (const auto it = key_to_idx.find("eacfn"); it != key_to_idx.end() && !loaded[it->second].bear_imports.empty()) {
            const auto& bimps = loaded[it->second].bear_imports;
            md << "## 3. Reconstructed `.bearimp` Kernel Import Table (`eacfn.sys` — `" << bimps.size() << "` Imports)\n\n";
            md << "| # | Module | Function | IAT RVA |\n";
            md << "|---|---|---|---|\n";
            for (size_t i = 0; i < bimps.size(); ++i) {
                md << "| `" << (i + 1) << "` | `" << bimps[i].dll_name
                   << "` | `" << bimps[i].func_name
                   << "` | `" << hex_u32(bimps[i].iat_rva) << "` |\n";
            }
            md << "\n";
        }

        md << eac::format_scan_markdown(driver_scans);
        md << eac::format_protocol_markdown(cipher_res, catalog_info, eossdk_rep, p_v159, p_v153);

        const auto md_path = out_dir / "VERIFICATION_REPORT.md";
        {
            std::ofstream ofs(md_path, std::ios::binary);
            ofs << md.str();
        }
        std::cout << "[WROTE] " << md_path.string() << "\n";

        // 2. Write verified_rvas.json
        std::ostringstream js;
        js << "{\n";
        js << "  \"overall_passed\": " << (all_ok ? "true" : "false") << ",\n";
        js << "  \"kernel_checks_passed\": " << passed_checks << ",\n";
        js << "  \"kernel_checks_total\": " << total_checks << ",\n";
        js << "  \"rolling_cipher_selftest\": {\n";
        js << "    \"passed\": " << (cipher_res.passed ? "true" : "false") << ",\n";
        js << "    \"tested_sizes\": " << cipher_res.tested_sizes << ",\n";
        js << "    \"detail\": \"" << json_escape(cipher_res.detail) << "\"\n";
        js << "  },\n";
        js << "  \"base_bin_catalog\": {\n";
        js << "    \"valid_magic\": " << (catalog_info.valid_magic ? "true" : "false") << ",\n";
        js << "    \"version\": " << catalog_info.version << ",\n";
        js << "    \"total_size\": " << catalog_info.total_size << ",\n";
        js << "    \"sha256\": \"" << json_escape(catalog_info.sha256) << "\"\n";
        js << "  },\n";
        js << "  \"binaries\": [\n";
        for (size_t i = 0; i < loaded.size(); ++i) {
            const auto& lt = loaded[i];
            js << "    {\n";
            js << "      \"key\": \"" << json_escape(lt.spec.key) << "\",\n";
            js << "      \"path\": \"" << json_escape(lt.spec.path) << "\",\n";
            js << "      \"arch\": \"" << (lt.pe.is_pe64() ? "x86_64" : "x86") << "\",\n";
            js << "      \"file_size\": " << lt.pe.raw_bytes().size() << ",\n";
            js << "      \"image_base\": \"" << hex_u64(lt.pe.image_base()) << "\",\n";
            js << "      \"size_of_image\": \"" << hex_u32(lt.pe.size_of_image()) << "\",\n";
            js << "      \"entry_rva\": \"" << hex_u32(lt.pe.entry_rva()) << "\",\n";
            js << "      \"time_date_stamp\": \"" << hex_u32(lt.pe.time_date_stamp()) << "\",\n";
            js << "      \"pdata_entries\": " << lt.pdata_count << ",\n";
            js << "      \"standard_imports\": " << lt.std_imports.size() << ",\n";
            js << "      \"bearimp_imports\": " << lt.bear_imports.size() << ",\n";
            js << "      \"exports\": " << lt.exports.size() << ",\n";
            js << "      \"sha256\": \"" << json_escape(lt.sha256) << "\"\n";
            js << "    }" << (i + 1 < loaded.size() ? "," : "") << "\n";
        }
        js << "  ],\n";
        js << "  \"driver_scans\": [\n";
        for (size_t i = 0; i < driver_scans.size(); ++i) {
            const auto& ds = driver_scans[i];
            js << "    {\n";
            js << "      \"label\": \"" << json_escape(ds.label) << "\",\n";
            js << "      \"cpuid_text_count\": " << ds.cpuid_rvas_text.size() << ",\n";
            js << "      \"cpuid_sec7_count\": " << ds.cpuid_rvas_sec7.size() << ",\n";
            js << "      \"rsmb_rdata_rvas\": [";
            for (size_t j = 0; j < ds.rsmb_rdata_rvas.size(); ++j) {
                if (j > 0) js << ", ";
                js << "\"" << hex_u32(ds.rsmb_rdata_rvas[j]) << "\"";
            }
            js << "],\n";
            js << "      \"ioctl_storage_2d1400_rvas\": [";
            for (size_t j = 0; j < ds.ioctl_storage_2d1400_rvas.size(); ++j) {
                if (j > 0) js << ", ";
                js << "\"" << hex_u32(ds.ioctl_storage_2d1400_rvas[j]) << "\"";
            }
            js << "],\n";
            js << "      \"smart_rvas\": [";
            for (size_t j = 0; j < ds.smart_7c088_or_7c084_rvas.size(); ++j) {
                if (j > 0) js << ", ";
                js << "\"" << hex_u32(ds.smart_7c088_or_7c084_rvas[j]) << "\"";
            }
            js << "],\n";
            js << "      \"kuser_reads\": [\n";
            for (size_t j = 0; j < ds.kuser_hits.size(); ++j) {
                const auto& kh = ds.kuser_hits[j];
                js << "        {\"insn_rva\": \"" << hex_u32(kh.insn_rva)
                   << "\", \"offset\": \"" << hex_u32(kh.kuser_offset)
                   << "\", \"field\": \"" << json_escape(kh.field_name)
                   << "\", \"section\": \"" << json_escape(kh.section_name) << "\"}"
                   << (j + 1 < ds.kuser_hits.size() ? "," : "") << "\n";
            }
            js << "      ],\n";
            js << "      \"checks\": [\n";
            for (size_t j = 0; j < ds.checks.size(); ++j) {
                const auto& c = ds.checks[j];
                js << "        {\"name\": \"" << json_escape(c.check_name)
                   << "\", \"rva\": \"" << hex_u32(c.rva)
                   << "\", \"passed\": " << (c.passed ? "true" : "false")
                   << ", \"observed_hex\": \"" << json_escape(c.observed_hex) << "\"}"
                   << (j + 1 < ds.checks.size() ? "," : "") << "\n";
            }
            js << "      ]\n";
            js << "    }" << (i + 1 < driver_scans.size() ? "," : "") << "\n";
        }
        js << "  ],\n";
        js << "  \"eossdk_anticheat_exports\": {\n";
        js << "    \"client_count\": " << eossdk_rep.client_export_count << ",\n";
        js << "    \"server_count\": " << eossdk_rep.server_export_count << ",\n";
        js << "    \"client\": [\n";
        for (size_t i = 0; i < eossdk_rep.client_exports.size(); ++i) {
            const auto& e = eossdk_rep.client_exports[i];
            js << "      {\"name\": \"" << json_escape(e.name) << "\", \"ordinal\": " << e.ordinal
               << ", \"rva\": \"" << hex_u32(e.rva) << "\"}"
               << (i + 1 < eossdk_rep.client_exports.size() ? "," : "") << "\n";
        }
        js << "    ],\n";
        js << "    \"server\": [\n";
        for (size_t i = 0; i < eossdk_rep.server_exports.size(); ++i) {
            const auto& e = eossdk_rep.server_exports[i];
            js << "      {\"name\": \"" << json_escape(e.name) << "\", \"ordinal\": " << e.ordinal
               << ", \"rva\": \"" << hex_u32(e.rva) << "\"}"
               << (i + 1 < eossdk_rep.server_exports.size() ? "," : "") << "\n";
        }
        js << "    ]\n";
        js << "  }\n";
        js << "}\n";

        const auto js_path = out_dir / "verified_rvas.json";
        {
            std::ofstream ofs(js_path, std::ios::binary);
            ofs << js.str();
        }
        std::cout << "[WROTE] " << js_path.string() << "\n";
    }

    return all_ok ? 0 : 1;
}
