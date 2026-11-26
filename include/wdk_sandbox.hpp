#pragma once
#include "pe_image.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace eac {

struct StubCallEvent {
    uint64_t step_index = 0;
    uint32_t caller_rva = 0;
    std::string module_name;
    std::string func_name;
    uint64_t rcx = 0;
    uint64_t rdx = 0;
    uint64_t r8 = 0;
    uint64_t r9 = 0;
    uint64_t ret_value = 0;
};

struct CpuidTraceEvent {
    uint64_t step_index = 0;
    uint32_t insn_rva = 0;
    uint32_t leaf_eax = 0;
    uint32_t subleaf_ecx = 0;
    uint32_t out_eax = 0;
    uint32_t out_ebx = 0;
    uint32_t out_ecx = 0;
    uint32_t out_edx = 0;
};

struct SandboxRunResult {
    std::string label;
    std::string path;
    bool engine_loaded = false;
    bool mapped_ok = false;
    uint32_t start_rva = 0;
    uint32_t last_rva = 0;
    uint64_t instructions_executed = 0;
    uint64_t basic_blocks_entered = 0;
    uint64_t sec7_instructions = 0;
    uint64_t text_instructions = 0;
    uint64_t relocations_applied = 0;
    uint64_t auto_mapped_pages = 0;
    uint64_t kuser_reads = 0;
    int uc_error_code = 0;
    std::string stop_reason;
    std::vector<StubCallEvent> stub_calls;
    std::vector<CpuidTraceEvent> cpuid_events;
    std::vector<std::string> sample_trace;
};

struct SandboxConfig {
    std::string unicorn_dll_path =
        R"(C:\Users\Administrator\.unsloth\studio\unsloth_studio\Lib\site-packages\unicorn\lib\unicorn.dll)";
    uint64_t mapped_base = 0x0000000140000000ULL;
    uint64_t max_instructions = 25000;
    bool apply_base_relocations = true;
    bool wire_bearimp_stubs = true;
    uint32_t os_build_number = 26100;
};

SandboxRunResult run_wdk_driver_sandbox(
    const std::string& label,
    const PeImage& pe,
    uint32_t start_rva,
    const SandboxConfig& cfg = {});

std::string format_sandbox_markdown(const std::vector<SandboxRunResult>& runs);

} // namespace eac
