#include "wdk_sandbox.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace eac {

namespace {

// Verified Unicorn 2.x x86_64 C ABI constants & function pointers
struct uc_struct;
using uc_engine = uc_struct;
using uc_hook = size_t;
using uc_err = int;

constexpr int kUcArchX86 = 4;
constexpr int kUcMode64 = 8;
constexpr uint32_t kUcProtAll = 7;
constexpr uc_err kUcErrOk = 0;

constexpr int kUcHookIntr = 1;
constexpr int kUcHookInsn = 2;
constexpr int kUcHookCode = 4;
constexpr int kUcHookBlock = 8;
constexpr int kUcHookMemUnmapped = 112;
constexpr int kUcHookMemRead = 1024;

constexpr int kUcRegEax = 19;
constexpr int kUcRegEbx = 21;
constexpr int kUcRegEcx = 22;
constexpr int kUcRegEdx = 24;
constexpr int kUcRegRax = 35;
constexpr int kUcRegRbp = 36;
constexpr int kUcRegRbx = 37;
constexpr int kUcRegRcx = 38;
constexpr int kUcRegRdi = 39;
constexpr int kUcRegRdx = 40;
constexpr int kUcRegRip = 41;
constexpr int kUcRegRsi = 43;
constexpr int kUcRegRsp = 44;
constexpr int kUcRegR8  = 106;
constexpr int kUcRegR9  = 107;
constexpr int kUcRegR12 = 110;
constexpr int kUcRegIdtr = 242;
constexpr int kUcRegGdtr = 243;
constexpr int kUcRegGsBase = 251;

struct UcX86Mmr {
    uint16_t selector;
    uint64_t base;
    uint32_t limit;
    uint32_t flags;
};

constexpr int kUcInsnCpuid = 113;

using fn_uc_open_t      = uc_err (*)(int arch, int mode, uc_engine** uc);
using fn_uc_close_t     = uc_err (*)(uc_engine* uc);
using fn_uc_mem_map_t   = uc_err (*)(uc_engine* uc, uint64_t address, uint64_t size, uint32_t perms);
using fn_uc_mem_write_t = uc_err (*)(uc_engine* uc, uint64_t address, const void* bytes, uint64_t size);
using fn_uc_mem_read_t  = uc_err (*)(uc_engine* uc, uint64_t address, void* bytes, uint64_t size);
using fn_uc_reg_write_t = uc_err (*)(uc_engine* uc, int regid, const void* value);
using fn_uc_reg_read_t  = uc_err (*)(uc_engine* uc, int regid, void* value);
using fn_uc_hook_add_t  = uc_err (*)(uc_engine* uc, uc_hook* hh, int type, void* callback,
                                     void* user_data, uint64_t begin, uint64_t end, ...);
using fn_uc_emu_start_t = uc_err (*)(uc_engine* uc, uint64_t begin, uint64_t until,
                                     uint64_t timeout, size_t count);
using fn_uc_emu_stop_t  = uc_err (*)(uc_engine* uc);
using fn_uc_strerror_t  = const char* (*)(uc_err code);

struct UnicornDynamicApi {
    HMODULE mod = nullptr;
    fn_uc_open_t open = nullptr;
    fn_uc_close_t close = nullptr;
    fn_uc_mem_map_t mem_map = nullptr;
    fn_uc_mem_write_t mem_write = nullptr;
    fn_uc_mem_read_t mem_read = nullptr;
    fn_uc_reg_write_t reg_write = nullptr;
    fn_uc_reg_read_t reg_read = nullptr;
    fn_uc_hook_add_t hook_add = nullptr;
    fn_uc_emu_start_t emu_start = nullptr;
    fn_uc_emu_stop_t emu_stop = nullptr;
    fn_uc_strerror_t strerror = nullptr;

    bool load(const std::string& dll_path) {
        mod = ::LoadLibraryA(dll_path.c_str());
        if (!mod) {
            mod = ::LoadLibraryA("unicorn.dll");
        }
        if (!mod) {
            return false;
        }
        auto sym = [&](const char* name) -> void* {
            return reinterpret_cast<void*>(::GetProcAddress(mod, name));
        };
        open      = reinterpret_cast<fn_uc_open_t>(sym("uc_open"));
        close     = reinterpret_cast<fn_uc_close_t>(sym("uc_close"));
        mem_map   = reinterpret_cast<fn_uc_mem_map_t>(sym("uc_mem_map"));
        mem_write = reinterpret_cast<fn_uc_mem_write_t>(sym("uc_mem_write"));
        mem_read  = reinterpret_cast<fn_uc_mem_read_t>(sym("uc_mem_read"));
        reg_write = reinterpret_cast<fn_uc_reg_write_t>(sym("uc_reg_write"));
        reg_read  = reinterpret_cast<fn_uc_reg_read_t>(sym("uc_reg_read"));
        hook_add  = reinterpret_cast<fn_uc_hook_add_t>(sym("uc_hook_add"));
        emu_start = reinterpret_cast<fn_uc_emu_start_t>(sym("uc_emu_start"));
        emu_stop  = reinterpret_cast<fn_uc_emu_stop_t>(sym("uc_emu_stop"));
        strerror  = reinterpret_cast<fn_uc_strerror_t>(sym("uc_strerror"));

        return open && close && mem_map && mem_write && mem_read &&
               reg_write && reg_read && hook_add && emu_start && emu_stop && strerror;
    }

    ~UnicornDynamicApi() {
        if (mod) {
            ::FreeLibrary(mod);
            mod = nullptr;
        }
    }
};

inline uint16_t read_u16_le(const uint8_t* p) noexcept {
    uint16_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

inline uint32_t read_u32_le(const uint8_t* p) noexcept {
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

inline uint64_t read_u64_le(const uint8_t* p) noexcept {
    uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

inline void write_u16_le(uint8_t* p, uint16_t v) noexcept {
    std::memcpy(p, &v, sizeof(v));
}

inline void write_u32_le(uint8_t* p, uint32_t v) noexcept {
    std::memcpy(p, &v, sizeof(v));
}

inline void write_u64_le(uint8_t* p, uint64_t v) noexcept {
    std::memcpy(p, &v, sizeof(v));
}

constexpr uint64_t align_down_4k(uint64_t v) noexcept {
    return v & ~0xFFFULL;
}

constexpr uint64_t align_up_4k(uint64_t v) noexcept {
    return (v + 0xFFFULL) & ~0xFFFULL;
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

std::string bytes_to_hex(const uint8_t* p, size_t n) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(p[i]);
    }
    return oss.str();
}

struct DataDirPair {
    uint32_t rva = 0;
    uint32_t size = 0;
};

DataDirPair read_pe64_data_dir(const PeImage& pe, uint32_t dir_idx) {
    DataDirPair out{};
    const auto raw = pe.raw_bytes();
    if (!pe.is_pe64() || raw.size() < 0x100) {
        return out;
    }
    const uint32_t lfanew = read_u32_le(raw.data() + 0x3C);
    if (static_cast<size_t>(lfanew) + 24 + 112 > raw.size()) {
        return out;
    }
    const uint16_t opt_sz = read_u16_le(raw.data() + lfanew + 4 + 16);
    const size_t opt_off = static_cast<size_t>(lfanew) + 24;
    if (opt_off + opt_sz > raw.size() || opt_sz < 112) {
        return out;
    }
    const uint32_t num_dirs = read_u32_le(raw.data() + opt_off + 108);
    if (dir_idx >= num_dirs) {
        return out;
    }
    const size_t dd_off = opt_off + 112 + static_cast<size_t>(dir_idx) * 8;
    if (dd_off + 8 > opt_off + opt_sz) {
        return out;
    }
    out.rva = read_u32_le(raw.data() + dd_off);
    out.size = read_u32_le(raw.data() + dd_off + 4);
    return out;
}

uint64_t apply_pe64_relocations(
    const PeImage& pe,
    std::vector<uint8_t>& mapped_img,
    uint64_t target_base) {
    const uint64_t orig_base = pe.image_base();
    if (orig_base == target_base) {
        return 0;
    }
    const DataDirPair reloc_dir = read_pe64_data_dir(pe, 5);
    if (reloc_dir.rva == 0 || reloc_dir.size < 8) {
        return 0;
    }
    if (static_cast<size_t>(reloc_dir.rva) + reloc_dir.size > mapped_img.size()) {
        return 0;
    }

    const int64_t delta = static_cast<int64_t>(target_base - orig_base);
    uint64_t applied = 0;
    size_t pos = reloc_dir.rva;
    const size_t end = reloc_dir.rva + reloc_dir.size;

    while (pos + 8 <= end) {
        const uint32_t page_rva = read_u32_le(mapped_img.data() + pos);
        const uint32_t block_sz = read_u32_le(mapped_img.data() + pos + 4);
        if (block_sz < 8 || pos + block_sz > end) {
            break;
        }
        const size_t entry_count = (block_sz - 8) / 2;
        const uint8_t* entries = mapped_img.data() + pos + 8;
        for (size_t i = 0; i < entry_count; ++i) {
            const uint16_t type_off = read_u16_le(entries + i * 2);
            const uint16_t type = (type_off >> 12) & 0xFU;
            const uint16_t off  = type_off & 0x0FFFU;
            if (type == 10) { // IMAGE_REL_BASED_DIR64
                const size_t patch_rva = static_cast<size_t>(page_rva) + off;
                if (patch_rva + 8 <= mapped_img.size()) {
                    const uint64_t cur = read_u64_le(mapped_img.data() + patch_rva);
                    write_u64_le(mapped_img.data() + patch_rva,
                                 static_cast<uint64_t>(static_cast<int64_t>(cur) + delta));
                    ++applied;
                }
            }
        }
        pos += block_sz;
    }
    return applied;
}

void init_security_cookie_in_image(
    const PeImage& pe,
    std::vector<uint8_t>& mapped_img,
    uint64_t target_base) {
    const DataDirPair lc_dir = read_pe64_data_dir(pe, 10);
    if (lc_dir.rva == 0 || static_cast<size_t>(lc_dir.rva) + 0x60 > mapped_img.size()) {
        return;
    }
    const uint64_t cookie_va = read_u64_le(mapped_img.data() + lc_dir.rva + 0x58);
    uint64_t cookie_rva = 0;
    if (cookie_va >= target_base && (cookie_va - target_base) + 16 <= mapped_img.size()) {
        cookie_rva = cookie_va - target_base;
    } else if (cookie_va >= pe.image_base() && (cookie_va - pe.image_base()) + 16 <= mapped_img.size()) {
        cookie_rva = cookie_va - pe.image_base();
    } else {
        return;
    }

    constexpr uint64_t kCustomCookie = 0x00007A4E91C3B82DULL;
    write_u64_le(mapped_img.data() + cookie_rva, kCustomCookie);
    write_u64_le(mapped_img.data() + cookie_rva + 8, ~kCustomCookie);
}

struct StubEntryDesc {
    std::string module_name;
    std::string func_name;
    uint64_t stub_addr = 0;
};

struct SandboxRuntimeCtx {
    UnicornDynamicApi* api = nullptr;
    SandboxRunResult* res = nullptr;
    uint64_t mapped_base = 0;
    uint64_t mapped_size = 0;
    uint32_t text_start = 0;
    uint32_t text_end = 0;
    uint32_t sec7_start = 0;
    uint32_t sec7_end = 0;
    uint64_t ret_sentinel = 0;
    uint64_t stub_base = 0;
    uint64_t stub_end = 0;
    uint64_t pool_cursor = 0;
    uint64_t pool_limit = 0;
    uint64_t dummy_ntos_base = 0;
    uint64_t max_instructions = 25000;
    uint32_t os_build_number = 26100;
    uint32_t zero_slide_run = 0;
    std::unordered_map<uint64_t, StubEntryDesc> addr_to_stub;
    std::set<uint64_t> mapped_pages;
};

uint64_t emulate_kernel_stub(
    uc_engine* uc,
    SandboxRuntimeCtx* ctx,
    const StubEntryDesc& stub,
    uint64_t rcx,
    uint64_t rdx,
    uint64_t r8,
    uint64_t r9) {
    const auto& fn = stub.func_name;

    if (fn == "ExAllocatePoolWithTag" || fn == "ExAllocatePool2" || fn == "ExAllocatePool") {
        uint64_t req_sz = (fn == "ExAllocatePool2") ? rdx : rdx;
        if (req_sz == 0 || req_sz > 0x100000ULL) {
            req_sz = 0x1000ULL;
        }
        const uint64_t aligned = (req_sz + 0xFULL) & ~0xFULL;
        if (ctx->pool_cursor + aligned <= ctx->pool_limit) {
            const uint64_t out_ptr = ctx->pool_cursor;
            ctx->pool_cursor += aligned;
            return out_ptr;
        }
        return 0;
    }

    if (fn == "RtlInitUnicodeString" || fn == "RtlInitUnicodeStringEx") {
        if (rcx != 0) {
            uint16_t byte_len = 0;
            if (rdx != 0) {
                uint16_t wbuf[256]{};
                if (ctx->api->mem_read(uc, rdx, wbuf, sizeof(wbuf)) == kUcErrOk) {
                    for (size_t i = 0; i < 255; ++i) {
                        if (wbuf[i] == 0) break;
                        byte_len += 2;
                    }
                }
            }
            uint8_t ustr[16]{};
            write_u16_le(ustr + 0, byte_len);
            write_u16_le(ustr + 2, static_cast<uint16_t>(byte_len + 2));
            write_u64_le(ustr + 8, rdx);
            ctx->api->mem_write(uc, rcx, ustr, sizeof(ustr));
        }
        return 0; // STATUS_SUCCESS
    }

    if (fn == "PsGetVersion") {
        const uint32_t maj = 10;
        const uint32_t min = 0;
        const uint32_t bld = ctx->os_build_number;
        if (rcx != 0) ctx->api->mem_write(uc, rcx, &maj, sizeof(maj));
        if (rdx != 0) ctx->api->mem_write(uc, rdx, &min, sizeof(min));
        if (r8 != 0)  ctx->api->mem_write(uc, r8,  &bld, sizeof(bld));
        return 0; // FALSE (retail build)
    }

    if (fn == "RtlGetVersion") {
        if (rcx != 0) {
            uint8_t osvi[0x11C]{};
            write_u32_le(osvi + 0x00, 0x11CU);
            write_u32_le(osvi + 0x04, 10U);
            write_u32_le(osvi + 0x08, 0U);
            write_u32_le(osvi + 0x0C, ctx->os_build_number);
            write_u32_le(osvi + 0x10, 2U);
            ctx->api->mem_write(uc, rcx, osvi, sizeof(osvi));
        }
        return 0;
    }

    if (fn == "KeQuerySystemTimePrecise" || fn == "KeQueryInterruptTimePrecise") {
        const uint64_t ticks = 0x01DC6E3AD4A51000ULL + ctx->res->instructions_executed * 100ULL;
        if (rcx != 0) {
            ctx->api->mem_write(uc, rcx, &ticks, sizeof(ticks));
        }
        return ticks;
    }

    if (fn == "KeGetCurrentIrql") {
        return 0; // PASSIVE_LEVEL
    }

    if (fn == "PsGetCurrentProcessId") {
        return 4; // System PID
    }

    if (fn == "PsGetCurrentThreadId") {
        return 0x104;
    }

    if (fn == "MmGetSystemRoutineAddress") {
        // Return a safe stub pointer at the end of the stub table (generic NTSTATUS=0 stub)
        return ctx->stub_base;
    }

    if (fn == "FltRegisterFilter") {
        if (r8 != 0) {
            const uint64_t fake_filter = 0x00007FF805001000ULL;
            ctx->api->mem_write(uc, r8, &fake_filter, sizeof(fake_filter));
        }
        return 0; // STATUS_SUCCESS
    }

    if (fn == "NtQuerySystemInformation" || fn == "ZwQuerySystemInformation") {
        // SystemModuleInformation (11) or SystemFirmwareTableInformation (76)
        if (r9 != 0) {
            const uint32_t ret_len = (r8 >= 0x40) ? 0x40U : 0x200U;
            ctx->api->mem_write(uc, r9, &ret_len, sizeof(ret_len));
        }
        if (rcx == 11 && rdx != 0 && r8 >= 0x130) {
            uint8_t mod_buf[0x130]{};
            write_u32_le(mod_buf + 0x00, 1U); // NumberOfModules = 1
            write_u64_le(mod_buf + 0x18, ctx->dummy_ntos_base); // ImageBase
            write_u32_le(mod_buf + 0x20, 0x01000000U); // ImageSize
            write_u16_le(mod_buf + 0x2A, 21U); // OffsetToFileName
            const char* mod_path = "\\SystemRoot\\system32\\ntoskrnl.exe";
            std::memcpy(mod_buf + 0x2C, mod_path, std::strlen(mod_path));
            ctx->api->mem_write(uc, rdx, mod_buf, sizeof(mod_buf));
            return 0;
        }
        return 0;
    }

    (void)r9;
    return 0; // Default STATUS_SUCCESS / NULL-safe status
}

void cb_hook_block(uc_engine* /*uc*/, uint64_t /*address*/, uint32_t /*size*/, void* user_data) {
    auto* ctx = static_cast<SandboxRuntimeCtx*>(user_data);
    ++ctx->res->basic_blocks_entered;
}

int cb_hook_cpuid(uc_engine* uc, void* user_data) {
    auto* ctx = static_cast<SandboxRuntimeCtx*>(user_data);
    uint64_t rip = 0;
    uint32_t leaf = 0;
    uint32_t subleaf = 0;
    ctx->api->reg_read(uc, kUcRegRip, &rip);
    ctx->api->reg_read(uc, kUcRegEax, &leaf);
    ctx->api->reg_read(uc, kUcRegEcx, &subleaf);

    uint32_t out_a = 0;
    uint32_t out_b = 0;
    uint32_t out_c = 0;
    uint32_t out_d = 0;

    if (leaf == 0) {
        out_a = 0x16U;
        out_b = 0x756E6547U; // "Genu"
        out_d = 0x49656E69U; // "ineI"
        out_c = 0x6C65746EU; // "ntel"
    } else if (leaf == 1) {
        out_a = 0x000A0655U; // Comet Lake / modern x86_64 stepping
        out_b = 0x00100800U;
        out_c = 0x7FFAFBBFU; // SSE3..AVX, RDRAND, Hypervisor=0 (bare metal)
        out_d = 0xBFEBFBFFU; // FPU, TSC, MSR,FXSR, SSE, SSE2
    } else if (leaf == 7 && subleaf == 0) {
        out_b = 0x029C67AFU; // BMI1, AVX2, SMEP, BMI2, ERMS, SMAP
        out_c = 0x00000000U;
        out_d = 0xBC000400U;
    } else if (leaf == 0x80000000U) {
        out_a = 0x80000008U;
    } else if (leaf == 0x80000001U) {
        out_c = 0x00000121U;
        out_d = 0x2C100800U; // SYSCALL, NX, LM
    } else if (leaf >= 0x80000002U && leaf <= 0x80000004U) {
        const char* brand = "Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz       ";
        const size_t idx = (leaf - 0x80000002U) * 16U;
        out_a = read_u32_le(reinterpret_cast<const uint8_t*>(brand + idx + 0));
        out_b = read_u32_le(reinterpret_cast<const uint8_t*>(brand + idx + 4));
        out_c = read_u32_le(reinterpret_cast<const uint8_t*>(brand + idx + 8));
        out_d = read_u32_le(reinterpret_cast<const uint8_t*>(brand + idx + 12));
    } else if (leaf == 0x80000008U) {
        out_a = 0x00003027U; // 39-bit phys, 48-bit linear
    }

    const uint64_t a64 = out_a;
    const uint64_t b64 = out_b;
    const uint64_t c64 = out_c;
    const uint64_t d64 = out_d;
    ctx->api->reg_write(uc, kUcRegRax, &a64);
    ctx->api->reg_write(uc, kUcRegRbx, &b64);
    ctx->api->reg_write(uc, kUcRegRcx, &c64);
    ctx->api->reg_write(uc, kUcRegRdx, &d64);

    if (ctx->res->cpuid_events.size() < 64) {
        CpuidTraceEvent ev;
        ev.step_index = ctx->res->instructions_executed;
        ev.insn_rva = (rip >= ctx->mapped_base && rip < ctx->mapped_base + ctx->mapped_size)
                          ? static_cast<uint32_t>(rip - ctx->mapped_base)
                          : 0U;
        ev.leaf_eax = leaf;
        ev.subleaf_ecx = subleaf;
        ev.out_eax = out_a;
        ev.out_ebx = out_b;
        ev.out_ecx = out_c;
        ev.out_edx = out_d;
        ctx->res->cpuid_events.push_back(ev);
    }

    return 1; // Overwrite cpuid result
}

void cb_hook_intr(uc_engine* uc, uint32_t intno, void* user_data) {
    auto* ctx = static_cast<SandboxRuntimeCtx*>(user_data);
    uint64_t rcx = 0;
    ctx->api->reg_read(uc, kUcRegRcx, &rcx);
    std::ostringstream oss;
    oss << "interrupt_0x" << std::hex << std::uppercase << intno
        << " (rcx=0x" << rcx << ")";
    ctx->res->stop_reason = oss.str();
    ctx->api->emu_stop(uc);
}

void cb_hook_mem_read(uc_engine* /*uc*/, int /*type*/, uint64_t address, int /*size*/,
                      int64_t /*value*/, void* user_data) {
    const uint64_t masked52 = address & 0x000FFFFFFFFFFFFFULL;
    if ((masked52 & ~0x1FFFULL) == 0x000FF78000000000ULL) {
        auto* ctx = static_cast<SandboxRuntimeCtx*>(user_data);
        ++ctx->res->kuser_reads;
    }
}

bool cb_hook_mem_unmapped(uc_engine* uc, int type, uint64_t address, int /*size*/,
                          int64_t /*value*/, void* user_data) {
    auto* ctx = static_cast<SandboxRuntimeCtx*>(user_data);
    // Reject NULL-page dereferences or unmapped instruction fetches
    if (address < 0x10000ULL || type == 21 /* UC_MEM_FETCH_UNMAPPED */) {
        std::ostringstream oss;
        oss << (type == 21 ? "unmapped_exec_fetch_0x" : "null_page_fault_0x")
            << std::hex << std::uppercase << address;
        ctx->res->stop_reason = oss.str();
        ctx->api->emu_stop(uc);
        return false;
    }
    if (ctx->res->auto_mapped_pages >= 512) {
        ctx->res->stop_reason = "auto_map_quota_reached";
        ctx->api->emu_stop(uc);
        return false;
    }
    const uint64_t page = align_down_4k(address);
    if (ctx->mapped_pages.count(page) != 0) {
        return false;
    }
    if (ctx->api->mem_map(uc, page, 0x1000ULL, kUcProtAll) == kUcErrOk) {
        ctx->mapped_pages.insert(page);
        ++ctx->res->auto_mapped_pages;
        return true;
    }
    return false;
}

void cb_hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* ctx = static_cast<SandboxRuntimeCtx*>(user_data);

    if (address == ctx->ret_sentinel) {
        uint64_t rax = 0;
        ctx->api->reg_read(uc, kUcRegRax, &rax);
        std::ostringstream oss;
        oss << "clean_return_ntstatus_0x" << std::hex << std::uppercase << static_cast<uint32_t>(rax);
        ctx->res->stop_reason = oss.str();
        ctx->api->emu_stop(uc);
        return;
    }

    // Check if execution entered any synthesized kernel API stub or mapped export RVA
    if (const auto it = ctx->addr_to_stub.find(address); it != ctx->addr_to_stub.end()) {
        uint64_t rsp = 0, rcx = 0, rdx = 0, r8 = 0, r9 = 0;
        ctx->api->reg_read(uc, kUcRegRsp, &rsp);
        ctx->api->reg_read(uc, kUcRegRcx, &rcx);
        ctx->api->reg_read(uc, kUcRegRdx, &rdx);
        ctx->api->reg_read(uc, kUcRegR8, &r8);
        ctx->api->reg_read(uc, kUcRegR9, &r9);

        uint64_t ret_addr = 0;
        ctx->api->mem_read(uc, rsp, &ret_addr, sizeof(ret_addr));
        const uint32_t caller_rva =
            (ret_addr >= ctx->mapped_base && ret_addr < ctx->mapped_base + ctx->mapped_size)
                ? static_cast<uint32_t>(ret_addr - ctx->mapped_base)
                : 0U;

        const uint64_t rv = emulate_kernel_stub(uc, ctx, it->second, rcx, rdx, r8, r9);
        ctx->api->reg_write(uc, kUcRegRax, &rv);

        if (ctx->res->stub_calls.size() < 128) {
            StubCallEvent ev;
            ev.step_index = ctx->res->instructions_executed;
            ev.caller_rva = caller_rva;
            ev.module_name = it->second.module_name;
            ev.func_name = it->second.func_name;
            ev.rcx = rcx;
            ev.rdx = rdx;
            ev.r8 = r8;
            ev.r9 = r9;
            ev.ret_value = rv;
            ctx->res->stub_calls.push_back(std::move(ev));
        }
        // Every registered stub / code export starts with `0xC3` (`ret`), so Unicorn executes `ret` naturally
        return;
    }

    if (address < ctx->mapped_base || address >= ctx->mapped_base + ctx->mapped_size) {
        std::ostringstream oss;
        oss << "external_branch_0x" << std::hex << std::uppercase << address;
        ctx->res->stop_reason = oss.str();
        ctx->api->emu_stop(uc);
        return;
    }

    const uint32_t rva = static_cast<uint32_t>(address - ctx->mapped_base);
    ctx->res->last_rva = rva;

    if (ctx->res->instructions_executed >= ctx->max_instructions) {
        ctx->res->stop_reason = "instruction_budget_reached";
        ctx->api->emu_stop(uc);
        return;
    }

    ++ctx->res->instructions_executed;
    const bool in_sec7 = (rva >= ctx->sec7_start && rva < ctx->sec7_end);
    if (rva >= ctx->text_start && rva < ctx->text_end) {
        ++ctx->res->text_instructions;
    } else if (in_sec7) {
        ++ctx->res->sec7_instructions;
    }

    const bool want_trace = (ctx->res->sample_trace.size() < 48) &&
                            ((ctx->res->instructions_executed <= 24) ||
                             (ctx->res->sec7_instructions >= 1 && ctx->res->sec7_instructions <= 24));
    if (want_trace || ctx->res->instructions_executed <= 128) {
        const uint32_t read_len = std::min<uint32_t>(std::max<uint32_t>(size, 1U), 16U);
        uint8_t insn_bytes[16]{};
        if (ctx->api->mem_read(uc, address, insn_bytes, read_len) != kUcErrOk) {
            ctx->res->stop_reason = "insn_mem_read_failed";
            ctx->api->emu_stop(uc);
            return;
        }
        if (read_len >= 2 && insn_bytes[0] == 0x00 && insn_bytes[1] == 0x00) {
            ++ctx->zero_slide_run;
            if (ctx->zero_slide_run >= 3) {
                ctx->res->stop_reason = "zero_page_slide_detected";
                ctx->api->emu_stop(uc);
                return;
            }
        } else {
            ctx->zero_slide_run = 0;
        }
        if (want_trace) {
            std::ostringstream line;
            line << "step=" << std::setw(4) << ctx->res->instructions_executed
                 << " RVA=0x" << std::hex << std::uppercase << std::setw(7) << std::setfill('0') << rva
                 << std::dec << std::setfill(' ')
                 << (in_sec7 ? " [Sec[7]] " : " [.text]  ")
                 << bytes_to_hex(insn_bytes, read_len);
            ctx->res->sample_trace.push_back(line.str());
        }
    }
}

} // namespace

SandboxRunResult run_wdk_driver_sandbox(
    const std::string& label,
    const PeImage& pe,
    uint32_t start_rva,
    const SandboxConfig& cfg) {
    SandboxRunResult res;
    res.label = label;
    res.path = pe.path();
    res.start_rva = (start_rva != 0) ? start_rva : pe.entry_rva();

    if (!pe.is_pe64() || pe.size_of_image() == 0) {
        res.stop_reason = "unsupported_pe_format";
        return res;
    }

    UnicornDynamicApi api;
    if (!api.load(cfg.unicorn_dll_path)) {
        res.stop_reason = "unicorn_dll_load_failed";
        return res;
    }
    res.engine_loaded = true;

    uc_engine* uc = nullptr;
    uc_err err = api.open(kUcArchX86, kUcMode64, &uc);
    if (err != kUcErrOk || !uc) {
        res.uc_error_code = err;
        res.stop_reason = "uc_open_failed";
        return res;
    }

    const uint64_t mapped_base = align_down_4k(cfg.mapped_base);
    const uint64_t mapped_size = align_up_4k(pe.size_of_image());

    // Build relocated in-memory image buffer
    std::vector<uint8_t> img_buf(static_cast<size_t>(mapped_size), 0);
    const auto raw = pe.raw_bytes();
    const size_t hdr_copy = std::min<size_t>(0x1000U, raw.size());
    std::memcpy(img_buf.data(), raw.data(), hdr_copy);

    uint32_t text_start = 0, text_end = 0;
    uint32_t sec7_start = 0, sec7_end = 0;
    const auto& secs = pe.sections();
    for (size_t i = 0; i < secs.size(); ++i) {
        const auto& s = secs[i];
        if (i == 0 || s.name == ".text") {
            text_start = s.virtual_address;
            text_end = s.virtual_address + std::max(s.virtual_size, s.raw_size);
        }
        if (i == 7) {
            sec7_start = s.virtual_address;
            sec7_end = s.virtual_address + std::max(s.virtual_size, s.raw_size);
        }
        if (s.raw_size > 0 && s.raw_ptr < raw.size()) {
            const size_t avail = std::min<size_t>(s.raw_size, raw.size() - s.raw_ptr);
            if (static_cast<size_t>(s.virtual_address) + avail <= img_buf.size()) {
                std::memcpy(img_buf.data() + s.virtual_address, raw.data() + s.raw_ptr, avail);
            }
        }
    }

    if (cfg.apply_base_relocations) {
        res.relocations_applied = apply_pe64_relocations(pe, img_buf, mapped_base);
    }

    // Initialize valid non-default __security_cookie & complement in .data so GsDriverEntry succeeds cleanly
    init_security_cookie_in_image(pe, img_buf, mapped_base);

    // Map driver image into Unicorn
    err = api.mem_map(uc, mapped_base, mapped_size, kUcProtAll);
    if (err != kUcErrOk) {
        res.uc_error_code = err;
        res.stop_reason = "uc_mem_map_image_failed";
        api.close(uc);
        return res;
    }
    api.mem_write(uc, mapped_base, img_buf.data(), img_buf.size());

    // Map WDM kernel regions:
    // 1. Stack:            0x00007FF801000000 (512 KB)
    // 2. WDK objects/GS:   0x00007FF802000000 (256 KB: _DRIVER_OBJECT, RegistryPath, _KPCR/_KPRCB/_KTHREAD/_EPROCESS, ret_sentinel)
    // 3. Stub trampolines: 0x00007FF803000000 (64 KB)
    // 4. Pool heap:        0x00007FF804000000 (2 MB)
    // 5. Dummy ntoskrnl:   0x00007FF806000000 (64 KB MZ/PE header for module base walks)
    // 6. KUSER_SHARED_DATA:0xFFFFF78000000000 (8 KB)
    constexpr uint64_t kStackBase = 0x00007FF801000000ULL;
    constexpr uint64_t kStackSize = 0x00080000ULL;
    constexpr uint64_t kRspInit   = kStackBase + 0x00060000ULL;

    constexpr uint64_t kWdkBase   = 0x00007FF802000000ULL;
    constexpr uint64_t kWdkSize   = 0x00040000ULL;
    constexpr uint64_t kDriverObj = kWdkBase + 0x01000ULL;
    constexpr uint64_t kRegPath   = kWdkBase + 0x02000ULL;
    constexpr uint64_t kKpcrBase  = kWdkBase + 0x04000ULL;
    constexpr uint64_t kKprcbBase = kKpcrBase + 0x0180ULL;
    constexpr uint64_t kKthread   = kWdkBase + 0x08000ULL;
    constexpr uint64_t kEprocess  = kWdkBase + 0x09000ULL;
    constexpr uint64_t kR12Frame  = kWdkBase + 0x10000ULL;
    constexpr uint64_t kRetSent   = kWdkBase + 0x38000ULL;

    constexpr uint64_t kStubBase  = 0x00007FF803000000ULL;
    constexpr uint64_t kStubSize  = 0x00010000ULL;

    constexpr uint64_t kPoolBase  = 0x00007FF804000000ULL;
    constexpr uint64_t kPoolSize  = 0x00200000ULL;

    constexpr uint64_t kFilterRgn  = 0x00007FF805000000ULL;
    constexpr uint64_t kDummyNtos  = 0x00007FF810000000ULL;
    constexpr uint64_t kDummyFlt   = 0x00007FF820000000ULL;

    constexpr uint64_t kKuserBase  = 0xFFFFF78000000000ULL;
    constexpr uint64_t kKuserAlias = 0x000FF78000000000ULL; // 52-bit QEMU x86_64 physical TLB mask alias

    api.mem_map(uc, kStackBase,  kStackSize, kUcProtAll);
    api.mem_map(uc, kWdkBase,    kWdkSize,   kUcProtAll);
    api.mem_map(uc, kStubBase,   kStubSize,  kUcProtAll);
    api.mem_map(uc, kPoolBase,   kPoolSize,  kUcProtAll);
    api.mem_map(uc, kFilterRgn,  0x10000ULL, kUcProtAll);
    api.mem_map(uc, kKuserBase,  0x2000ULL,  kUcProtAll);
    api.mem_map(uc, kKuserAlias, 0x2000ULL,  kUcProtAll);

    res.mapped_ok = true;

    // Load & cache host ntoskrnl.exe and fltmgr.sys PE images so InLoadOrderLinks + PE export parsing resolve cleanly
    static const std::optional<PeImage> s_ntos_pe = PeImage::load_from_file(R"(C:\Windows\System32\ntoskrnl.exe)");
    static const std::optional<PeImage> s_flt_pe  = PeImage::load_from_file(R"(C:\Windows\System32\drivers\fltmgr.sys)");

    auto map_dep_module = [&](const std::optional<PeImage>& dep_opt, uint64_t mod_base, uint32_t& out_img_sz) {
        if (!dep_opt.has_value() || !dep_opt->is_pe64()) {
            out_img_sz = 0x10000U;
            api.mem_map(uc, mod_base, 0x10000ULL, kUcProtAll);
            uint8_t fake_pe[0x200]{};
            write_u16_le(fake_pe + 0x00, 0x5A4DU);
            write_u32_le(fake_pe + 0x3C, 0x80U);
            write_u32_le(fake_pe + 0x80, 0x00004550U);
            write_u16_le(fake_pe + 0x84, 0x8664U);
            write_u16_le(fake_pe + 0x94, 0xF0U);
            write_u16_le(fake_pe + 0x98, 0x20BU);
            write_u64_le(fake_pe + 0xB0, mod_base);
            write_u32_le(fake_pe + 0xD0, out_img_sz);
            api.mem_write(uc, mod_base, fake_pe, sizeof(fake_pe));
            return;
        }
        const auto& dep = *dep_opt;
        const uint64_t sz = align_up_4k(dep.size_of_image());
        out_img_sz = static_cast<uint32_t>(sz);
        api.mem_map(uc, mod_base, sz, kUcProtAll);
        const auto dep_raw = dep.raw_bytes();
        api.mem_write(uc, mod_base, dep_raw.data(), std::min<size_t>(0x1000U, dep_raw.size()));
        for (const auto& sec : dep.sections()) {
            if (sec.raw_size > 0 && sec.raw_ptr < dep_raw.size()) {
                const size_t avail = std::min<size_t>(sec.raw_size, dep_raw.size() - sec.raw_ptr);
                if (static_cast<uint64_t>(sec.virtual_address) + avail <= sz) {
                    api.mem_write(uc, mod_base + sec.virtual_address, dep_raw.data() + sec.raw_ptr, avail);
                }
            }
        }
    };

    uint32_t ntos_img_sz = 0;
    uint32_t flt_img_sz  = 0;
    map_dep_module(s_ntos_pe, kDummyNtos, ntos_img_sz);
    map_dep_module(s_flt_pe,  kDummyFlt,  flt_img_sz);

    // Populate return sentinel (`ret; int3; int3; int3`)
    const uint8_t ret_ops[4] = {0xC3, 0xCC, 0xCC, 0xCC};
    api.mem_write(uc, kRetSent, ret_ops, sizeof(ret_ops));
    api.mem_write(uc, kRspInit, &kRetSent, sizeof(kRetSent));

    // Populate _DRIVER_OBJECT, _DRIVER_EXTENSION, and circular InLoadOrderLinks (_KLDR_DATA_TABLE_ENTRY ring)
    {
        const uint64_t drv_ext  = kWdkBase + 0x1800ULL;
        const uint64_t ldr_drv  = kWdkBase + 0x3000ULL;
        const uint64_t ldr_ntos = kWdkBase + 0x3200ULL;
        const uint64_t ldr_flt  = kWdkBase + 0x3400ULL;
        uint64_t str_cursor     = kWdkBase + 0x3800ULL;

        auto write_ldr_node = [&](uint64_t node_va, uint64_t flink, uint64_t blink,
                                  uint64_t dll_base, uint64_t entry_va, uint32_t size_of_img,
                                  const wchar_t* full_w, const wchar_t* base_w) {
            uint8_t ldr[0x100]{};
            write_u64_le(ldr + 0x00, flink);
            write_u64_le(ldr + 0x08, blink);
            write_u64_le(ldr + 0x30, dll_base);
            write_u64_le(ldr + 0x38, entry_va);
            write_u32_le(ldr + 0x40, size_of_img);

            const uint16_t full_bytes = static_cast<uint16_t>(std::wcslen(full_w) * 2U);
            const uint64_t full_ptr = str_cursor;
            str_cursor += align_up_4k(full_bytes + 4U) > 0x100ULL ? 0x100ULL : 0x100ULL;
            api.mem_write(uc, full_ptr, full_w, full_bytes + 2U);
            write_u16_le(ldr + 0x48, full_bytes);
            write_u16_le(ldr + 0x4A, static_cast<uint16_t>(full_bytes + 2U));
            write_u64_le(ldr + 0x50, full_ptr);

            const uint16_t base_bytes = static_cast<uint16_t>(std::wcslen(base_w) * 2U);
            const uint64_t base_ptr = str_cursor;
            str_cursor += 0x100ULL;
            api.mem_write(uc, base_ptr, base_w, base_bytes + 2U);
            write_u16_le(ldr + 0x58, base_bytes);
            write_u16_le(ldr + 0x5A, static_cast<uint16_t>(base_bytes + 2U));
            write_u64_le(ldr + 0x60, base_ptr);

            api.mem_write(uc, node_va, ldr, sizeof(ldr));
        };

        write_ldr_node(ldr_drv, ldr_ntos, ldr_flt, mapped_base, mapped_base + res.start_rva, pe.size_of_image(),
                       L"\\SystemRoot\\System32\\drivers\\EasyAntiCheat_EOS.sys", L"EasyAntiCheat_EOS.sys");
        write_ldr_node(ldr_ntos, ldr_flt, ldr_drv, kDummyNtos, kDummyNtos + 0x1000ULL, ntos_img_sz,
                       L"\\SystemRoot\\system32\\ntoskrnl.exe", L"ntoskrnl.exe");
        write_ldr_node(ldr_flt, ldr_drv, ldr_ntos, kDummyFlt, kDummyFlt + 0x1000ULL, flt_img_sz,
                       L"\\SystemRoot\\System32\\drivers\\fltmgr.sys", L"fltmgr.sys");

        uint8_t ext_buf[0x40]{};
        write_u64_le(ext_buf + 0x00, kDriverObj);
        api.mem_write(uc, drv_ext, ext_buf, sizeof(ext_buf));

        uint8_t drv_obj[0x150]{};
        write_u16_le(drv_obj + 0x00, 4U);
        write_u16_le(drv_obj + 0x02, 0x150U);
        write_u64_le(drv_obj + 0x18, mapped_base);
        write_u32_le(drv_obj + 0x20, pe.size_of_image());
        write_u64_le(drv_obj + 0x28, ldr_drv);
        write_u64_le(drv_obj + 0x30, drv_ext);
        api.mem_write(uc, kDriverObj, drv_obj, sizeof(drv_obj));
    }

    // Populate _UNICODE_STRING RegistryPath ("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\EasyAntiCheat_EOSSys")
    {
        const wchar_t* reg_w = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\EasyAntiCheat_EOSSys";
        const size_t wchars = std::wcslen(reg_w);
        const uint16_t byte_len = static_cast<uint16_t>(wchars * 2U);
        const uint64_t str_buf = kRegPath + 0x40ULL;
        api.mem_write(uc, str_buf, reg_w, byte_len + 2U);
        uint8_t ustr[16]{};
        write_u16_le(ustr + 0, byte_len);
        write_u16_le(ustr + 2, static_cast<uint16_t>(byte_len + 2U));
        write_u64_le(ustr + 8, str_buf);
        api.mem_write(uc, kRegPath, ustr, sizeof(ustr));
    }

    // Populate _KPCR / _KPRCB / _KIDTENTRY64[256] / _KTHREAD / _EPROCESS at GS_BASE
    {
        const uint64_t kIdtBase = kWdkBase + 0x05000ULL;
        const uint64_t kGdtBase = kWdkBase + 0x06000ULL;
        const uint64_t isr_va   = kDummyNtos + std::min<uint64_t>(0x00100000ULL, ntos_img_sz > 0x2000U ? 0x2000ULL : 0x1000ULL);
        uint8_t idt_page[0x1000]{};
        for (size_t vec = 0; vec < 256; ++vec) {
            uint8_t* ent = idt_page + vec * 16;
            write_u16_le(ent + 0x00, static_cast<uint16_t>(isr_va & 0xFFFFULL));         // OffsetLow
            write_u16_le(ent + 0x02, 0x0010U);                                           // Selector (KGDT64_R0_CODE)
            ent[0x04] = 0x00U;                                                           // IstIndex
            ent[0x05] = 0x8EU;                                                           // Type=0xE (64-bit intr gate), DPL=0, P=1
            write_u16_le(ent + 0x06, static_cast<uint16_t>((isr_va >> 16) & 0xFFFFULL)); // OffsetMiddle
            write_u32_le(ent + 0x08, static_cast<uint32_t>((isr_va >> 32) & 0xFFFFFFFFULL)); // OffsetHigh
        }
        api.mem_write(uc, kIdtBase, idt_page, sizeof(idt_page));

        api.mem_write(uc, kKpcrBase + 0x000, &kGdtBase,  sizeof(kGdtBase));  // GdtBase
        api.mem_write(uc, kKpcrBase + 0x018, &kKpcrBase, sizeof(kKpcrBase)); // Self
        api.mem_write(uc, kKpcrBase + 0x020, &kKprcbBase, sizeof(kKprcbBase)); // CurrentPrcb
        api.mem_write(uc, kKpcrBase + 0x038, &kIdtBase,  sizeof(kIdtBase));  // IdtBase (gs:[0x38] -> vector 0x0E KiPageFault)
        api.mem_write(uc, kKpcrBase + 0x188, &kKthread,  sizeof(kKthread));  // Prcb.CurrentThread (gs:[0x188])
        api.mem_write(uc, kKthread  + 0x0B8, &kEprocess, sizeof(kEprocess)); // ApcState.Process
        api.mem_write(uc, kKthread  + 0x220, &kEprocess, sizeof(kEprocess)); // Process
        const uint64_t sys_pid = 4ULL;
        api.mem_write(uc, kEprocess + 0x440, &sys_pid, sizeof(sys_pid));
        api.reg_write(uc, kUcRegGsBase, &kKpcrBase);

        const UcX86Mmr idtr{0U, kIdtBase, 0x0FFFU, 0U};
        const UcX86Mmr gdtr{0U, kGdtBase, 0x007FU, 0U};
        api.reg_write(uc, kUcRegIdtr, &idtr);
        api.reg_write(uc, kUcRegGdtr, &gdtr);
    }

    // Populate KUSER_SHARED_DATA (0xFFFFF78000000000)
    {
        const uint64_t intr_time = 0x000000018A4C2B10ULL;
        const uint32_t sys_time[3] = {0xD4A51000U, 0x01DC6E3AU, 0x01DC6E3AU};
        const uint32_t build_num = cfg.os_build_number;
        uint8_t proc_feats[64]{};
        proc_feats[0] = 1; proc_feats[1] = 1; proc_feats[2] = 1; proc_feats[3] = 1;
        const uint8_t zero_byte = 0;
        const uint64_t tick_cnt = 0x0000000004B87F10ULL;

        for (uint64_t kb : {kKuserBase, kKuserAlias}) {
            api.mem_write(uc, kb + 0x008, &intr_time, sizeof(intr_time));
            api.mem_write(uc, kb + 0x014, sys_time, sizeof(sys_time));
            api.mem_write(uc, kb + 0x260, &build_num, sizeof(build_num));
            api.mem_write(uc, kb + 0x274, proc_feats, sizeof(proc_feats));
            api.mem_write(uc, kb + 0x2D4, &zero_byte, 1); // KdDebuggerEnabled = 0
            api.mem_write(uc, kb + 0x2EC, &zero_byte, 1); // SafeBootMode = 0
            api.mem_write(uc, kb + 0x320, &tick_cnt, sizeof(tick_cnt));
        }
    }

    // Build kernel API stub trampoline table for standard imports, .bearimp imports, and ntoskrnl/fltmgr exports
    SandboxRuntimeCtx ctx;
    ctx.api = &api;
    ctx.res = &res;
    ctx.mapped_base = mapped_base;
    ctx.mapped_size = mapped_size;
    ctx.text_start = text_start;
    ctx.text_end = text_end;
    ctx.sec7_start = sec7_start;
    ctx.sec7_end = sec7_end;
    ctx.ret_sentinel = kRetSent;
    ctx.stub_base = kStubBase;
    ctx.pool_cursor = kPoolBase;
    ctx.pool_limit = kPoolBase + kPoolSize;
    ctx.dummy_ntos_base = kDummyNtos;
    ctx.max_instructions = cfg.max_instructions;
    ctx.os_build_number = cfg.os_build_number;

    uint64_t next_stub = kStubBase;
    auto alloc_stub = [&](const std::string& mod_name, const std::string& fn_name, uint32_t iat_rva) {
        if (next_stub + 16 > kStubBase + kStubSize) {
            return;
        }
        const uint64_t addr = next_stub;
        next_stub += 16;
        // Write `ret; int3; ...` at stub address; cb_hook_code sets RAX before `ret` executes
        const uint8_t stub_code[4] = {0xC3, 0xCC, 0xCC, 0xCC};
        api.mem_write(uc, addr, stub_code, sizeof(stub_code));
        ctx.addr_to_stub[addr] = StubEntryDesc{mod_name, fn_name, addr};

        if (iat_rva != 0 && static_cast<uint64_t>(iat_rva) + 8 <= mapped_size) {
            api.mem_write(uc, mapped_base + iat_rva, &addr, sizeof(addr));
        }
    };

    // Slot 0: generic fallback routine for MmGetSystemRoutineAddress
    alloc_stub("ntoskrnl.exe", "<MmGetSystemRoutineFallback>", 0);

    for (const auto& imp : pe.parse_standard_imports()) {
        alloc_stub(imp.dll_name, imp.func_name, imp.iat_rva);
    }
    if (cfg.wire_bearimp_stubs) {
        for (const auto& imp : pe.parse_bearimp_imports()) {
            alloc_stub(imp.dll_name, imp.func_name, imp.iat_rva);
        }
    }
    ctx.stub_end = next_stub;

    auto register_dep_exports = [&](const std::optional<PeImage>& dep_opt, uint64_t mod_base,
                                    uint32_t mod_sz, const std::string& mod_name) {
        if (!dep_opt.has_value() || !dep_opt->is_pe64()) {
            return;
        }
        const auto& dep = *dep_opt;
        const auto& dsecs = dep.sections();
        auto is_exec_rva = [&](uint32_t rva) -> bool {
            for (const auto& s : dsecs) {
                const uint32_t span = std::max(s.virtual_size, s.raw_size);
                if (rva >= s.virtual_address && (rva - s.virtual_address) < span) {
                    return (s.characteristics & 0x20000000U) != 0; // IMAGE_SCN_MEM_EXECUTE
                }
            }
            return false;
        };
        const uint8_t ret_byte = 0xC3;
        for (const auto& ex : dep.parse_exports()) {
            if (ex.is_forwarded || ex.rva == 0 || ex.rva >= mod_sz) {
                continue;
            }
            if (is_exec_rva(ex.rva)) {
                const uint64_t target_va = mod_base + ex.rva;
                api.mem_write(uc, target_va, &ret_byte, 1);
                ctx.addr_to_stub[target_va] = StubEntryDesc{mod_name, ex.name, target_va};
            }
        }
    };

    register_dep_exports(s_ntos_pe, kDummyNtos, ntos_img_sz, "ntoskrnl.exe");
    register_dep_exports(s_flt_pe,  kDummyFlt,  flt_img_sz,  "fltmgr.sys");

    // Initialize registers for WDM DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
    const uint64_t rbp_init = kRspInit + 0x200ULL;
    const uint64_t r8_init  = 0ULL;
    const uint64_t r9_init  = 0ULL;
    api.reg_write(uc, kUcRegRsp, &kRspInit);
    api.reg_write(uc, kUcRegRbp, &rbp_init);
    api.reg_write(uc, kUcRegRcx, &kDriverObj);
    api.reg_write(uc, kUcRegRdx, &kRegPath);
    api.reg_write(uc, kUcRegR8,  &r8_init);
    api.reg_write(uc, kUcRegR9,  &r9_init);
    api.reg_write(uc, kUcRegR12, &kR12Frame);
    api.reg_write(uc, kUcRegRax, &mapped_base);

    // Register Unicorn hooks
    uc_hook hh_block = 0, hh_cpuid = 0, hh_intr = 0, hh_kuser = 0, hh_unmap = 0, hh_code = 0;
    api.hook_add(uc, &hh_block, kUcHookBlock, reinterpret_cast<void*>(&cb_hook_block), &ctx, 1ULL, 0ULL);
    api.hook_add(uc, &hh_cpuid, kUcHookInsn,  reinterpret_cast<void*>(&cb_hook_cpuid), &ctx, 1ULL, 0ULL, kUcInsnCpuid);
    api.hook_add(uc, &hh_intr,  kUcHookIntr,  reinterpret_cast<void*>(&cb_hook_intr),  &ctx, 1ULL, 0ULL);
    api.hook_add(uc, &hh_kuser, kUcHookMemRead, reinterpret_cast<void*>(&cb_hook_mem_read), &ctx, 1ULL, 0ULL);
    api.hook_add(uc, &hh_unmap, kUcHookMemUnmapped, reinterpret_cast<void*>(&cb_hook_mem_unmapped), &ctx, 1ULL, 0ULL);
    api.hook_add(uc, &hh_code,  kUcHookCode,  reinterpret_cast<void*>(&cb_hook_code),  &ctx, 1ULL, 0ULL);

    const uint64_t entry_va = mapped_base + res.start_rva;
    err = api.emu_start(uc, entry_va, kRetSent, 0ULL, static_cast<size_t>(cfg.max_instructions + 64));
    res.uc_error_code = err;
    if (res.stop_reason.empty()) {
        if (err == kUcErrOk) {
            res.stop_reason = "completed_within_budget";
        } else {
            res.stop_reason = std::string("uc_err: ") + api.strerror(err);
        }
    }

    api.close(uc);
    return res;
}

std::string format_sandbox_markdown(const std::vector<SandboxRunResult>& runs) {
    std::ostringstream md;
    md << "## WDM Kernel Driver Sandbox Emulation (`wdk_sandbox` — C++20 + Unicorn x86_64)\n\n";
    md << "Full PE64 image mapping at `0x0000000140000000` with `IMAGE_REL_BASED_DIR64` base relocation rebasing, "
          "`LOAD_CONFIG` `__security_cookie` pre-initialization, synthesized `_DRIVER_OBJECT` (`RCX`), "
          "`_UNICODE_STRING RegistryPath` (`RDX`), `GS_BASE` (`_KPCR` / `_KPRCB` / `_KTHREAD` / `_EPROCESS`), "
          "`KUSER_SHARED_DATA` (`0xFFFFF78000000000`), `CPUID` bare-metal interception, and `.bearimp` / IAT kernel API trampolines.\n\n";

    md << "| Target | `StartRVA` | `LastRVA` | Insns Executed | `.text` Insns | `Sec[7]` Insns | Basic Blocks | Relocs Applied | Auto-Mapped Pages | `KUSER` Reads | `CPUID` Traps | Stub Calls | Stop Reason |\n";
    md << "|---|---|---|---|---|---|---|---|---|---|---|---|---|\n";
    for (const auto& r : runs) {
        md << "| `" << r.label
           << "` | `" << hex_u32(r.start_rva)
           << "` | `" << hex_u32(r.last_rva)
           << "` | `" << r.instructions_executed
           << "` | `" << r.text_instructions
           << "` | `" << r.sec7_instructions
           << "` | `" << r.basic_blocks_entered
           << "` | `" << r.relocations_applied
           << "` | `" << r.auto_mapped_pages
           << "` | `" << r.kuser_reads
           << "` | `" << r.cpuid_events.size()
           << "` | `" << r.stub_calls.size()
           << "` | `" << r.stop_reason << "` |\n";
    }
    md << "\n";

    for (const auto& r : runs) {
        md << "### Sandbox Run: `" << r.label << "` (`" << r.path << "`)\n\n";
        if (!r.cpuid_events.empty()) {
            md << "#### Intercepted `CPUID` Instructions (`" << r.cpuid_events.size() << "`)\n\n";
            md << "| Step | Insn RVA | Leaf (`EAX`) | Subleaf (`ECX`) | Out `EAX` | Out `EBX` | Out `ECX` | Out `EDX` |\n";
            md << "|---|---|---|---|---|---|---|---|\n";
            for (const auto& c : r.cpuid_events) {
                md << "| `" << c.step_index
                   << "` | `" << hex_u32(c.insn_rva)
                   << "` | `" << hex_u32(c.leaf_eax)
                   << "` | `" << hex_u32(c.subleaf_ecx)
                   << "` | `" << hex_u32(c.out_eax)
                   << "` | `" << hex_u32(c.out_ebx)
                   << "` | `" << hex_u32(c.out_ecx)
                   << "` | `" << hex_u32(c.out_edx) << "` |\n";
            }
            md << "\n";
        }

        if (!r.stub_calls.empty()) {
            md << "#### Intercepted Kernel Import Trampoline Calls (`" << r.stub_calls.size() << "`)\n\n";
            md << "| Step | Caller RVA | Module | Function | `RCX` | `RDX` | `R8` | Return (`RAX`) |\n";
            md << "|---|---|---|---|---|---|---|---|\n";
            const size_t lim = std::min<size_t>(r.stub_calls.size(), 30);
            for (size_t i = 0; i < lim; ++i) {
                const auto& sc = r.stub_calls[i];
                md << "| `" << sc.step_index
                   << "` | `" << hex_u32(sc.caller_rva)
                   << "` | `" << sc.module_name
                   << "` | `" << sc.func_name
                   << "` | `" << hex_u64(sc.rcx)
                   << "` | `" << hex_u64(sc.rdx)
                   << "` | `" << hex_u64(sc.r8)
                   << "` | `" << hex_u64(sc.ret_value) << "` |\n";
            }
            md << "\n";
        }

        if (!r.sample_trace.empty()) {
            md << "#### Sample Execution Trace (`GsDriverEntry` -> `Sec[7]` Transition)\n\n";
            md << "```text\n";
            for (const auto& ln : r.sample_trace) {
                md << ln << "\n";
            }
            md << "```\n\n";
        }
    }

    return md.str();
}

} // namespace eac
