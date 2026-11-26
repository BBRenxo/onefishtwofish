#pragma once
#include "pe_image.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace eac {

struct CatalogBaseBinInfo {
    bool valid_magic = false;
    uint32_t version = 0;
    size_t total_size = 0;
    std::string sha256;
    std::string header_hex;
    std::vector<std::string> extracted_strings;
};

struct EosSdkAntiCheatReport {
    size_t client_export_count = 0;
    size_t server_export_count = 0;
    std::vector<ExportEntry> client_exports;
    std::vector<ExportEntry> server_exports;
};

struct CipherSelfTestResult {
    bool passed = false;
    size_t tested_sizes = 0;
    std::string detail;
};

void eos_bin_rolling_decrypt(std::span<uint8_t> buf);
void eos_bin_rolling_encrypt(std::span<uint8_t> buf);
CipherSelfTestResult run_rolling_cipher_selftest();

uint64_t derive_prologue_kstate(uint64_t caller_seed, uint64_t c_mix) noexcept;
uint64_t decrypt_affine_pointer(uint64_t enc_slot_val, uint64_t c_mul, uint64_t k_state) noexcept;

CatalogBaseBinInfo parse_base_bin_catalog(const std::string& path);
EosSdkAntiCheatReport analyze_eossdk_exports(const PeImage& eossdk_pe);
std::string format_protocol_markdown(
    const CipherSelfTestResult& cipher_test,
    const CatalogBaseBinInfo& catalog_info,
    const EosSdkAntiCheatReport& eossdk_report,
    const PeImage* service_v159,
    const PeImage* service_v153_bak);

} // namespace eac
