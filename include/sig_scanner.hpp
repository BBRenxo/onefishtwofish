#pragma once
#include "pe_image.hpp"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace eac {

struct KuserReadHit {
    uint32_t insn_rva = 0;
    uint32_t kuser_offset = 0;
    std::string section_name;
    std::string field_name;
    uint8_t reg_code = 0;
};

struct AffineThunkHit {
    uint32_t thunk_rva = 0;
    uint64_t mul_const = 0;
    uint32_t table_slot_rva = 0;
    uint64_t slot_raw_value = 0;
    std::string section_name;
};

struct RvaVerificationCheck {
    std::string binary_label;
    std::string check_name;
    uint32_t rva = 0;
    bool passed = false;
    std::string observed_hex;
    std::string detail;
};

struct DriverScanSummary {
    std::string label;
    std::string path;
    std::vector<uint32_t> cpuid_rvas_text;
    std::vector<uint32_t> cpuid_rvas_sec7;
    std::vector<KuserReadHit> kuser_hits;
    std::vector<uint32_t> rsmb_rdata_rvas;
    std::vector<uint32_t> ioctl_storage_2d1400_rvas;
    std::vector<uint32_t> smart_7c088_or_7c084_rvas;
    std::vector<AffineThunkHit> affine_thunks_sample;
    std::vector<RvaVerificationCheck> checks;
};

std::vector<uint32_t> scan_pattern_rvas(const PeImage& pe, std::string_view ida_pattern, bool executable_only = false);
DriverScanSummary scan_kernel_driver(const std::string& label, const PeImage& pe);
std::string format_scan_markdown(const std::vector<DriverScanSummary>& summaries);

} // namespace eac
