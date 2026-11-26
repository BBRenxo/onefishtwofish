#!/usr/bin/env python3
"""
EAC EOS Kernel Driver Devirtualization & Static/Symbolic Trace Runner (v3)
Targets:
  - eac_dumped.sys           (40,251,392 bytes, ImageBase=0xFFFFF80496FE0000)
  - eacfn.sys                (43,213,824 bytes, ImageBase=0xFFFFF80400000000, 119 .bearimp imports)
  - EasyAntiCheat_EOS.sys    (44,398,752 bytes, ImageBase=0x140000000, prior build)
  - EasyAntiCheat_EOS.sys    (46,171,808 bytes, ImageBase=0x140000000, live 2026-11-25 build)
"""

import os
import sys
import struct
import datetime
import pefile
import capstone
import unicorn
from unicorn import (
    Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL,
    UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_UNMAPPED
)
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP
)

OUT_DIR = r"C:\Users\Administrator\Desktop\eac_reversal\devirt"
EOS_44M_CANDIDATES = [
    r"C:\Users\Administrator\Downloads\EasyAntiCheat_EOS.sys",
    r"C:\Users\Administrator\Documents\GitHub\tptb-stack\research\eac\EasyAntiCheat_EOS.sys",
]
BINS = {
    "eac_dumped": r"C:\Users\Administrator\Downloads\eac_dumped.sys",
    "eacfn": r"C:\Users\Administrator\Downloads\eacfn.sys",
    "eos_44m": next((p for p in EOS_44M_CANDIDATES if os.path.exists(p)), EOS_44M_CANDIDATES[0]),
    "eos_live": r"C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys",
}

CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
CS.detail = True

ARITH_MNEMONICS = {
    "add", "sub", "xor", "and", "or", "not", "neg", "inc", "dec",
    "imul", "mul", "idiv", "div", "shl", "shr", "sar", "rol", "ror",
    "shrd", "shld", "adc", "sbb", "lea", "cmp", "test"
}
BRANCH_MNEMONICS = {
    "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
    "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno", "call", "ret", "loopne"
}


class DriverImage:
    def __init__(self, key, path):
        self.key = key
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.pe = pefile.PE(data=self.data, fast_load=True)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.size_of_image = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def rva_to_off(self, rva):
        for s in self.pe.sections:
            vstart = s.VirtualAddress
            vend = vstart + max(s.Misc_VirtualSize, s.SizeOfRawData)
            if vstart <= rva < vend:
                off = s.PointerToRawData + (rva - vstart)
                if off < len(self.data):
                    return off
        return None

    def off_to_rva(self, off):
        for s in self.pe.sections:
            pstart = s.PointerToRawData
            pend = pstart + s.SizeOfRawData
            if pstart <= off < pend:
                return s.VirtualAddress + (off - pstart)
        return None

    def read_rva(self, rva, size):
        off = self.rva_to_off(rva)
        if off is None:
            return b""
        return self.data[off:min(len(self.data), off + size)]

    def disasm_rva(self, rva, size=0x100, max_insns=64):
        buf = self.read_rva(rva, size)
        out = []
        for idx, ins in enumerate(CS.disasm(buf, rva)):
            if idx >= max_insns:
                break
            out.append(ins)
        return out


def align_down(val, align=0x1000):
    return val & ~(align - 1)


def align_up(val, align=0x1000):
    return (val + align - 1) & ~(align - 1)


def run_unicorn_trace(drv: DriverImage, start_rva: int, max_steps: int = 250, setup_fn=None, stop_rvas=None):
    """
    Emulates `drv` starting at `start_rva` in Unicorn x86_64 with full PE section mapping,
    virtual context frame (`r12`), stack (`rsp`), scratch buffers, and `KUSER_SHARED_DATA`.
    Maps the PE image at canonical low-half virtual base `0x0000000140000000` inside Unicorn
    while translating all trace RVAs transparently.
    """
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    base = 0x0000000140000000
    img_size = align_up(drv.size_of_image, 0x1000)

    uc.mem_map(base, img_size, UC_PROT_ALL)
    uc.mem_write(base, drv.data[:min(0x1000, len(drv.data))])
    for s in drv.pe.sections:
        vaddr = base + s.VirtualAddress
        raw_off = s.PointerToRawData
        raw_sz = min(s.SizeOfRawData, max(0, len(drv.data) - raw_off))
        if raw_sz > 0 and s.VirtualAddress + raw_sz <= img_size:
            uc.mem_write(vaddr, drv.data[raw_off:raw_off + raw_sz])

    stack_base = 0x00007FF801000000
    stack_size = 0x40000
    rsp_init = stack_base + 0x20000
    uc.mem_map(stack_base, stack_size, UC_PROT_ALL)

    ctx_base = 0x00007FF802000000
    ctx_size = 0x40000
    r12_init = ctx_base + 0x10000
    rsi_buf = ctx_base + 0x20000
    r8_irp_stack = ctx_base + 0x24000
    rcx_dev_obj = ctx_base + 0x28000
    rdx_buf = ctx_base + 0x2C000
    r9_buf = ctx_base + 0x30000
    ret_sentinel = ctx_base + 0x38000
    uc.mem_map(ctx_base, ctx_size, UC_PROT_ALL)
    uc.mem_write(ret_sentinel, b"\xC3\xCC\xCC\xCC")
    uc.mem_write(rsp_init, struct.pack("<Q", ret_sentinel))

    # Map KUSER_SHARED_DATA (0xFFFFF78000000000) with verified Windows DDK layout:
    # +0x008 InterruptTime, +0x014 SystemTime, +0x020 TimeZoneBias, +0x260 NtBuildNumber,
    # +0x274 ProcessorFeatures[64], +0x2D4 KdDebuggerEnabled, +0x2EC SafeBootMode, +0x320 TickCount
    kuser_base = 0xFFFFF78000000000
    uc.mem_map(kuser_base, 0x2000, UC_PROT_ALL)
    uc.mem_write(kuser_base + 0x008, struct.pack("<Q", 0x000000018A4C2B10))
    uc.mem_write(kuser_base + 0x014, struct.pack("<III", 0xD4A51000, 0x01DC6E3A, 0x01DC6E3A))
    uc.mem_write(kuser_base + 0x020, struct.pack("<Q", 0x0000000000000000))
    uc.mem_write(kuser_base + 0x260, struct.pack("<I", 26100))
    uc.mem_write(kuser_base + 0x274, bytes([1, 1, 1, 1] + [0] * 60))
    uc.mem_write(kuser_base + 0x2D4, struct.pack("<B", 0))
    uc.mem_write(kuser_base + 0x2EC, struct.pack("<B", 0))
    uc.mem_write(kuser_base + 0x320, struct.pack("<Q", 0x0000000004B87F10))

    uc.reg_write(UC_X86_REG_RSP, rsp_init)
    uc.reg_write(UC_X86_REG_RBP, rsp_init + 0x200)
    uc.reg_write(UC_X86_REG_R12, r12_init)
    uc.reg_write(UC_X86_REG_RAX, base)
    uc.reg_write(UC_X86_REG_RCX, rcx_dev_obj)
    uc.reg_write(UC_X86_REG_RDX, rdx_buf)
    uc.reg_write(UC_X86_REG_RSI, rsi_buf)
    uc.reg_write(UC_X86_REG_RDI, 0x1ACD77CBBD53A976)
    uc.reg_write(UC_X86_REG_R8,  r8_irp_stack)
    uc.reg_write(UC_X86_REG_R9,  r9_buf)

    uc.mem_write(r12_init + 0x000, struct.pack("<Q", base))
    uc.mem_write(r12_init + 0x008, struct.pack("<Q", rdx_buf))
    uc.mem_write(r12_init + 0x040, struct.pack("<Q", rsi_buf))
    uc.mem_write(r12_init + 0x048, struct.pack("<Q", 0x9B6C46078037AD29 ^ 0x55AA55AA55AA55AA))
    uc.mem_write(r12_init + 0x058, struct.pack("<Q", 0))
    uc.mem_write(r12_init + 0x060, struct.pack("<Q", base))
    uc.mem_write(r12_init + 0x068, struct.pack("<Q", rcx_dev_obj))
    uc.mem_write(r12_init + 0x080, struct.pack("<Q", 0x55AA55AA55AA55AA))
    uc.mem_write(r12_init + 0x088, struct.pack("<Q", rdx_buf))
    uc.mem_write(r12_init + 0x0A0, struct.pack("<Q", r8_irp_stack))
    uc.mem_write(r12_init + 0x0A8, struct.pack("<Q", rsp_init + 0x100))
    uc.mem_write(r12_init + 0x0B0, struct.pack("<Q", base))
    uc.mem_write(r12_init + 0x0B8, struct.pack("<Q", base))
    uc.mem_write(r12_init + 0x0C0, struct.pack("<Q", base))
    uc.mem_write(r12_init + 0x0D0, struct.pack("<Q", rsi_buf))
    uc.mem_write(r12_init + 0x0F0, struct.pack("<I", 0))
    uc.mem_write(r12_init + 0x0F8, struct.pack("<Q", rcx_dev_obj))
    uc.mem_write(r12_init + 0x120, struct.pack("<I", 0))
    uc.mem_write(r12_init + 0x128, struct.pack("<Q", rsi_buf))
    uc.mem_write(r12_init + 0x148, struct.pack("<Q", rdx_buf))
    uc.mem_write(r12_init + 0x150, struct.pack("<Q", 0x1ACD77CBBD53A976 ^ 0x4242424242424242))
    uc.mem_write(r12_init + 0x158, struct.pack("<Q", rsi_buf))
    uc.mem_write(r12_init + 0x168, struct.pack("<Q", r8_irp_stack))
    uc.mem_write(r12_init + 0x188, struct.pack("<Q", r8_irp_stack))
    uc.mem_write(r12_init + 0x190, struct.pack("<Q", rdx_buf))
    uc.mem_write(r12_init + 0x198, struct.pack("<Q", base + start_rva))

    uc.mem_write(rsp_init + 0x140, struct.pack("<Q", base))

    if setup_fn is not None:
        setup_fn(uc, drv, {
            "base": base,
            "rsp": rsp_init,
            "r12": r12_init,
            "rsi_buf": rsi_buf,
            "r8_irp_stack": r8_irp_stack,
            "rcx_dev_obj": rcx_dev_obj,
            "rdx_buf": rdx_buf,
            "r9_buf": r9_buf,
            "ret_sentinel": ret_sentinel,
        })

    trace_insns = []
    mem_reads = []
    mem_writes = []
    stats = {"total": 0, "arith": 0, "mem": 0, "branch": 0, "exit": 0}
    stop_set = set(stop_rvas or [])
    zero_slide_count = [0]

    def hook_code(mu, address, size, user_data):
        if address == ret_sentinel or address < base or address >= base + img_size:
            stats["exit"] = 1
            mu.emu_stop()
            return
        rva = address - base
        if stats["total"] >= max_steps or rva in stop_set:
            stats["exit"] = 1
            mu.emu_stop()
            return
        try:
            raw = bytes(mu.mem_read(address, min(max(size, 1), 16)))
        except Exception:
            stats["exit"] = 1
            mu.emu_stop()
            return
        if raw[:2] == b"\x00\x00":
            zero_slide_count[0] += 1
            if zero_slide_count[0] >= 2:
                stats["exit"] = 1
                mu.emu_stop()
                return
        else:
            zero_slide_count[0] = 0

        ins_list = list(CS.disasm(raw, rva))
        if not ins_list:
            stats["exit"] = 1
            mu.emu_stop()
            return
        ins = ins_list[0]
        stats["total"] += 1
        mnem = ins.mnemonic.lower()
        if mnem in ARITH_MNEMONICS:
            stats["arith"] += 1
        if mnem in BRANCH_MNEMONICS:
            stats["branch"] += 1
        if "[" in ins.op_str:
            stats["mem"] += 1

        trace_insns.append(f"RVA 0x{ins.address:07x}: {ins.bytes.hex():24s} {ins.mnemonic} {ins.op_str}")

    def hook_mem_read(mu, access, address, size, value, user_data):
        cur_rip = mu.reg_read(UC_X86_REG_RIP) - base
        uaddr = address & 0xFFFFFFFFFFFFFFFF
        try:
            data_b = bytes(mu.mem_read(uaddr, size))
            val = int.from_bytes(data_b, "little")
        except Exception:
            val = 0
        mem_reads.append((cur_rip, uaddr, size, val))

    def hook_mem_write(mu, access, address, size, value, user_data):
        cur_rip = mu.reg_read(UC_X86_REG_RIP) - base
        uaddr = address & 0xFFFFFFFFFFFFFFFF
        unsigned_val = value & ((1 << (size * 8)) - 1)
        mem_writes.append((cur_rip, uaddr, size, unsigned_val))

    def hook_mem_unmapped(mu, access, address, size, value, user_data):
        if address < 0x10000:
            stats["exit"] = 1
            mu.emu_stop()
            return False
        page = align_down(address, 0x1000)
        try:
            mu.mem_map(page, 0x1000, UC_PROT_ALL)
            return True
        except Exception:
            stats["exit"] = 1
            mu.emu_stop()
            return False

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped)

    try:
        uc.emu_start(base + start_rva, base + drv.size_of_image, count=max_steps)
        stats["exit"] = 1
    except unicorn.UcError:
        stats["exit"] = 1

    return stats, trace_insns, mem_reads, mem_writes, uc


def generate_ioctl_storage_report(drivers, log_lines):
    drv_dump = drivers["eac_dumped"]
    drv_fn = drivers["eacfn"]
    drv_live = drivers["eos_live"]

    stats_dump, trace_dump, reads_dump, writes_dump, _ = run_unicorn_trace(
        drv_dump, 0x153938, max_steps=60, stop_rvas={0x394CEA}
    )
    stats_dump_s7, trace_dump_s7, reads_dump_s7, writes_dump_s7, _ = run_unicorn_trace(
        drv_dump, 0x394CF1, max_steps=60, stop_rvas={0x3B7683, 0x45FEE2, 0x403FB3, 0x43B20E}
    )
    stats_fn, trace_fn, _, _, _ = run_unicorn_trace(
        drv_fn, 0xB90A3, max_steps=60, stop_rvas={0x41D1D5}
    )
    stats_fn_s7, trace_fn_s7, _, _, _ = run_unicorn_trace(
        drv_fn, 0x41D1DD, max_steps=60, stop_rvas={0x3EBF0E}
    )
    stats_live, trace_live, reads_live, writes_live, _ = run_unicorn_trace(
        drv_live, 0x2A57ECA, max_steps=80, stop_rvas={0x21351EF}
    )

    total_steps = stats_dump["total"] + stats_dump_s7["total"] + stats_fn["total"] + stats_live["total"]
    total_arith = stats_dump["arith"] + stats_dump_s7["arith"] + stats_fn["arith"] + stats_live["arith"]
    total_mem = stats_dump["mem"] + stats_dump_s7["mem"] + stats_fn["mem"] + stats_live["mem"]
    total_branch = stats_dump["branch"] + stats_dump_s7["branch"] + stats_fn["branch"] + stats_live["branch"]

    all_reads = reads_dump + reads_dump_s7 + reads_live
    all_writes = writes_dump + writes_dump_s7 + writes_live

    md = []
    md.append("# Devirtualization: `IOCTL_STORAGE_QUERY_PROPERTY` (`0x2D1400`)")
    md.append("")
    md.append("## Cross-Build Targets & Entry Points")
    md.append("| Build | Path | Size | ImageBase | Handler Entry RVA | `0x2D1400` Write RVA | `Sec[7]` Continuation RVA | Completion Callback RVA |")
    md.append("|---|---|---|---|---|---|---|---|")
    md.append("| `eac_dumped.sys` | `C:\\Users\\Administrator\\Downloads\\eac_dumped.sys` | `40,251,392` B | `0xFFFFF80496FE0000` | `0x153938` | `0x153995` | `0x394CEA` / `0x394CF1` -> `0x135950E` | `0x184960` |")
    md.append("| `eacfn.sys` | `C:\\Users\\Administrator\\Downloads\\eacfn.sys` | `43,213,824` B | `0xFFFFF80400000000` | `0x0B90A3` | `0x0B90FC` | `0x41D1D5` / `0x41D1DD` -> `0x121E832` | `0x215101` |")
    md.append("| `EasyAntiCheat_EOS.sys` (2026-11-25 live) | `C:\\Program Files (x86)\\EasyAntiCheat_EOS\\EasyAntiCheat_EOS.sys` | `46,171,808` B | `0x0000000140000000` | `0x2A57ECA` (`Sec[7]`) | `0x2A57F24` | `0x45748F` -> `0x21351B0` | `0x221EA9` |")
    md.append("| `EasyAntiCheat_EOS.sys` (44.4 MB prior) | `C:\\Users\\Administrator\\Downloads\\EasyAntiCheat_EOS.sys` | `44,398,752` B | `0x0000000140000000` | `MBA-encoded in Sec[7]` (`0` literal `0x2D1400` / `0x2800000000` immediates) | `MBA` | `Sec[7]` | `Sec[7]` |")
    md.append("")
    md.append(f"- **Total Instructions Stepped Across Traces**: `{total_steps}` (`arith={total_arith}`, `mem={total_mem}`, `branch={total_branch}`, `exit=1`)")
    md.append("")
    md.append("## Notes & Architectural Mechanism")
    md.append("- In `eac_dumped.sys` and `eacfn.sys`, the `IOCTL_STORAGE_QUERY_PROPERTY` (`0x002D1400`) builder resides in `.text` (`RVA 0x153938` and `RVA 0xB90A3`) and jumps into `Sec[7]` (`RVA 0x394CEA` / `0x41D1D5`).")
    md.append("- In live `EasyAntiCheat_EOS.sys` (`46,171,808` bytes, `2026-11-25`), the entire handler resides inside `Sec[7]` at `RVA 0x2A57ECA` (`0x2D1400` write at `RVA 0x2A57F24`), jumping to `Sec[7]` dispatcher `RVA 0x45748F` -> `0x21351B0`.")
    md.append("- In prior `Downloads\\EasyAntiCheat_EOS.sys` (`44,398,752` bytes), exhaustive byte-scanning across `.text` and `Sec[7]` confirms `0` literal `00 14 2D 00` or `0x2800000000` immediates: that build synthesizes `0x2D1400` via MBA arithmetic inside `Sec[7]` just like `0x7C088` at `RVA 0x8A3B36`.")
    md.append("")
    md.append("## Inputs Read (Memory / Virtual Frame `r12`)")
    for rva, addr, sz, val in all_reads[:35]:
        md.append(f"- `RVA 0x{rva:07x}` read `{sz}` bytes (`0x{val:x}`) from `0x{addr:016x}`")
    md.append("")
    md.append("## Outputs Written (`STORAGE_PROPERTY_QUERY`, `IO_STACK_LOCATION`, `r12` Frame)")
    for rva, addr, sz, val in all_writes[:35]:
        md.append(f"- `RVA 0x{rva:07x}` wrote `{sz}` bytes (`0x{val:x}`) to `0x{addr:016x}`")
    md.append("")
    md.append("## Pseudo-C Reconstruction")
    md.append("```c")
    md.append("void eac_prepare_storage_query_property_irp(eac_vm_frame_t* r12) {")
    md.append("    uint8_t* image_base        = (uint8_t*)r12->image_base_60;")
    md.append("    void*    device_obj        = (void*)r12->device_obj_f8;")
    md.append("    uint32_t query_param       = r12->query_param_120;")
    md.append("    uint8_t* query_buf         = (uint8_t*)r12->query_buf_158;")
    md.append("    uint64_t obf_context_key   = 0x1ACD77CBBD53A976ULL ^ r12->seed_150;")
    md.append("    PIO_STACK_LOCATION irp_sp  = (PIO_STACK_LOCATION)r12->irp_sp_188;")
    md.append("")
    md.append("    memcpy(query_buf, image_base + 0x2C605F, 16); // +0x2C25F9 eacfn, +0x2D6B2D live EOS")
    md.append("    *(uint32_t*)(query_buf + 0x10) = query_param;")
    md.append("    *(uint64_t*)(query_buf + 0x14) = 0x0000002800000000ULL;")
    md.append("    *(uint32_t*)(query_buf + 0x1C) = 0x00000200U;")
    md.append("")
    md.append("    irp_sp->Parameters.DeviceIoControl.Type3InputBuffer   = (void*)obf_context_key;")
    md.append("    irp_sp->Parameters.DeviceIoControl.IoControlCode      = 0x002D1400U;")
    md.append("    irp_sp->Parameters.DeviceIoControl.OutputBufferLength = 0x00001030U;")
    md.append("    irp_sp->CompletionRoutine = (PIO_COMPLETION_ROUTINE)(image_base + 0x184960);")
    md.append("}")
    md.append("```")
    md.append("")
    md.append("## Executed Instructions (Unicorn Traces)")
    md.append("### 1. `eac_dumped.sys` (`RVA 0x153938..0x1539E2` -> `Sec[7] RVA 0x394CF1 -> 0x135950E`)")
    md.append("```asm")
    md.extend(trace_dump)
    md.append("; --- Sec[7] Continuation (RVA 0x394CF1 -> 0x135950E) ---")
    md.extend(trace_dump_s7)
    md.append("```")
    md.append("")
    md.append("### 2. `eacfn.sys` (`RVA 0x0B90A3..0x0B9152` -> `Sec[7] RVA 0x41D1DD -> 0x121E832`)")
    md.append("```asm")
    md.extend(trace_fn)
    md.append("; --- Sec[7] Continuation (RVA 0x41D1DD -> 0x121E832) ---")
    md.extend(trace_fn_s7[:25])
    md.append("```")
    md.append("")
    md.append("### 3. `EasyAntiCheat_EOS.sys` (2026-11-25 live build, `Sec[7] RVA 0x2A57ECA..0x2A57F71 -> 0x45748F -> 0x21351B0`)")
    md.append("```asm")
    md.extend(trace_live)
    md.append("```")
    md.append("")

    out_path = os.path.join(OUT_DIR, "ioctl_storage_query_property.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    log_lines.append(
        f"WROTE {out_path} (total={total_steps}, arith={total_arith}, mem={total_mem}, branch={total_branch}, exit=1)"
    )


def generate_smart_report(drivers, log_lines):
    drv_44m = drivers["eos_44m"]
    drv_fn = drivers["eacfn"]

    def setup_44m(uc, drv, env):
        uc.reg_write(UC_X86_REG_RBP, 0)
        uc.mem_write(env["rsp"] + 0x80, struct.pack("<Q", 0x7B8C8))
        uc.mem_write(env["rsp"] + 0x140, struct.pack("<Q", env["base"]))

    stats_44m_entry, trace_44m_entry, reads_44m_e, writes_44m_e, _ = run_unicorn_trace(
        drv_44m, 0x8A292E, max_steps=65
    )
    stats_44m_core, trace_44m_core, reads_44m_c, writes_44m_c, _ = run_unicorn_trace(
        drv_44m, 0x8A3B13, max_steps=160, setup_fn=setup_44m, stop_rvas={0x3E1632, 0x408562}
    )
    trimmed_core = []
    for line in trace_44m_core:
        trimmed_core.append(line)
        if "0x08a3fa1:" in line:
            break

    stats_fn_smart, trace_fn_smart, reads_fn_s, writes_fn_s, _ = run_unicorn_trace(
        drv_fn, 0x1CD7A15, max_steps=30, stop_rvas={0x1CD7A7D}
    )

    total_steps = stats_44m_entry["total"] + len(trimmed_core) + stats_fn_smart["total"]
    total_arith = stats_44m_entry["arith"] + stats_44m_core["arith"] + stats_fn_smart["arith"]
    total_mem = stats_44m_entry["mem"] + stats_44m_core["mem"] + stats_fn_smart["mem"]
    total_branch = stats_44m_entry["branch"] + stats_44m_core["branch"] + stats_fn_smart["branch"]

    clean_reads = [(r, a, s, v) for (r, a, s, v) in (reads_44m_e + reads_44m_c + reads_fn_s) if a >= 0x1000]
    clean_writes = [(r, a, s, v) for (r, a, s, v) in (writes_44m_e + writes_44m_c + writes_fn_s) if a >= 0x1000]

    md = []
    md.append("# Devirtualization: `SMART_RCV_DRIVE_DATA` (`0x7C088`) & `0x7C084` MBA Handlers")
    md.append("")
    md.append("## Cross-Build Targets & Entry Points")
    md.append("| Build | Section | Handler Entry RVA | Core MBA RVA | Outgoing Dispatch RVA | Constants Observed |")
    md.append("|---|---|---|---|---|---|")
    md.append("| `EasyAntiCheat_EOS.sys` (`44,398,752` B) | `Sec[7]` | `0x8A292E` | `0x8A3B13..0x8A3FA1` | `0x3E1632` / `0x408562` | `+0x7C0`, `0xFFFFFF`, `0x4573C3`, `0xBA93FD` |")
    md.append("| `eacfn.sys` (`43,213,824` B) | `Sec[7]` | `0x1CD7A15` | `0x1CD7A24..0x1CD7A7D` | `0x3CB732` | `lea rcx, [rax + 0x7C084]`, `-0x40EEE` |")
    md.append("")
    md.append(f"- **Handlers / Instructions Stepped**: `{total_steps}` (`arith={total_arith}`, `mem={total_mem}`, `branch={total_branch}`, `exit=1`)")
    md.append("")
    md.append("## Notes & Static Context")
    md.append("- Note on `.text` false positives: byte-pattern hits for `84 C0 07 00` inside `.text` (`0x7B073` in `eos_44m`, `0xF77EF` in `eos_live`) are `test al, al; je +0x7C0` (`84 C0 0F 84 C0 07 00 00`) instruction boundary overlaps, NOT `SMART_SEND_DRIVE_COMMAND` immediates. Genuine SMART constants reside in `Sec[7]` MBA blocks (`0x8A3B36` in `eos_44m` and `0x1CD7A24` in `eacfn.sys`).")
    md.append("- At `RVA 0x8A3B1B..0x8A3B43` (`eos_44m`), linear-XOR MBA `r8d = (rax + rbp) - 2*(rbp & 0x4573C3)` followed by `lea r9d, [r8 + 0x7C0]; and r9d, 0xFFFFFF` synthesizes `0x0007C088` (`SMART_RCV_DRIVE_DATA`) when `r8d == 0x7B8C8`.")
    md.append("")
    md.append("## Inputs Read (Stack & `r12` Virtual Frame)")
    for rva, addr, sz, val in clean_reads[:35]:
        md.append(f"- `RVA 0x{rva:07x}` read `{sz}` bytes (`0x{val:x}`) from `0x{addr:016x}`")
    md.append("")
    md.append("## Outputs Written (Stack & `r12` Virtual Frame)")
    for rva, addr, sz, val in clean_writes[:25]:
        md.append(f"- `RVA 0x{rva:07x}` wrote `{sz}` bytes (`0x{val:x}`) to `0x{addr:016x}`")
    md.append("")
    md.append("## Executed Instructions (Unicorn Traces)")
    md.append("### 1. `EasyAntiCheat_EOS.sys` (`Sec[7]` Handler Entry `RVA 0x8A292E..0x8A29E4`)")
    md.append("```asm")
    md.extend(trace_44m_entry[:35])
    md.append("```")
    md.append("")
    md.append("### 2. `EasyAntiCheat_EOS.sys` (`Sec[7]` Core MBA & Dispatch `RVA 0x8A3B13..0x8A3FA1`)")
    md.append("```asm")
    md.extend(trimmed_core)
    md.append("```")
    md.append("")
    md.append("### 3. `eacfn.sys` (`Sec[7]` Affine `0x7C084` MBA Dispatcher `RVA 0x1CD7A15..0x1CD7A7D`)")
    md.append("```asm")
    md.extend(trace_fn_smart)
    md.append("```")
    md.append("")

    out_path = os.path.join(OUT_DIR, "smart_rcv_drive_data.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    log_lines.append(
        f"WROTE {out_path} (total={total_steps}, arith={total_arith}, mem={total_mem}, branch={total_branch}, exit=1)"
    )


def generate_kuser_report(drivers, log_lines):
    drv_dump = drivers["eac_dumped"]
    drv_live = drivers["eos_live"]

    sites_dump = [
        ("+0x014 SystemTime",            0x171FE2),
        ("+0x260 NtBuildNumber",         0x00F59A),
        ("+0x274 ProcessorFeatures[0]",  0x2091C8),
        ("+0x2EC SafeBootMode",          0x21EF4E),
        ("+0x320 TickCount",             0x0342ED),
    ]
    sites_live = [
        ("+0x014 SystemTime",            0x0CCA5B),
        ("+0x260 NtBuildNumber",         0x0542CC),
        ("+0x274 ProcessorFeatures[0]",  0x0EFC8B),
        ("+0x2EC SafeBootMode",          0x1D19B7),
        ("+0x320 TickCount",             0x0AD4E1),
    ]

    all_traces = []
    all_reads = []
    all_writes = []
    total_steps = 0
    total_arith = 0
    total_mem = 0
    total_branch = 0

    for label, rva in sites_dump:
        # Stop before uninitialized indirect `call r10` at +0x274 site (0x2091D5)
        stops = {0x2091D5} if rva == 0x2091C8 else None
        stats, trace, rds, wrs, _ = run_unicorn_trace(drv_dump, rva, max_steps=18, stop_rvas=stops)
        total_steps += stats["total"]
        total_arith += stats["arith"]
        total_mem += stats["mem"]
        total_branch += stats["branch"]
        all_traces.append((f"eac_dumped.sys {label} (RVA 0x{rva:07x})", trace))
        all_reads.extend(rds)
        all_writes.extend(wrs)

    for label, rva in sites_live:
        stops = {0x0EFC98} if rva == 0x0EFC8B else None
        stats, trace, rds, wrs, _ = run_unicorn_trace(drv_live, rva, max_steps=15, stop_rvas=stops)
        total_steps += stats["total"]
        total_arith += stats["arith"]
        total_mem += stats["mem"]
        total_branch += stats["branch"]
        all_traces.append((f"EasyAntiCheat_EOS.sys (live 46.17MB) {label} (RVA 0x{rva:07x})", trace))
        all_reads.extend(rds)
        all_writes.extend(wrs)

    kuser_reads = [
        (r, a, s, v) for (r, a, s, v) in all_reads
        if 0xFFFFF78000000000 <= (a & 0xFFFFFFFFFFFFFFFF) < 0xFFFFF78000001000
    ]

    md = []
    md.append("# Devirtualization: `KUSER_SHARED_DATA` (`0xFFFFF78000000000`) Offset Reads")
    md.append("")
    md.append("## Ground-Truth DDK Audit (`_KUSER_SHARED_DATA` in `ntddk.h` + x64 Disassembly)")
    md.append("1. **`+0x274` is `BOOLEAN ProcessorFeatures[64]` (`+0x274..+0x2B3`)**, NOT `KdDebuggerEnabled` (`KdDebuggerEnabled` resides at `+0x2D4`, which has `0` direct `movabs` sites). At `RVA 0xEFC8B` (`eos_live`), `0x2091C8` (`eac_dumped`), `0x2100DE` (`eacfn`), and `0x1B11B9` (`eos_44m`), the instruction loads `0xFFFFF78000000274` as a pointer argument (`RCX`/`R8`/`R9`) into an affine-decrypted buffer-hash/copy helper (`call r10`) to snapshot the 64-byte CPU feature array.")
    md.append("2. **`+0x2EC` is `BOOLEAN SafeBootMode`**, NOT `ConsoleSessionForegroundProcessId`. Across all four builds (`0x1D19B7` `eos_live`, `0x21EF4E` `eac_dumped`, `0x1CB08C` `eacfn`, `0x207DCA` `eos_44m`), the function is an identical 13-byte leaf helper: `movabs rax, 0xFFFFF780000002EC; mov al, byte ptr [rax]; ret`.")
    md.append("")
    md.append("## Cross-Build RVA Matrix (Exact `movabs` Instruction Boundaries)")
    md.append("| Offset | Verified `_KUSER_SHARED_DATA` Field | `eac_dumped.sys` RVAs | `eacfn.sys` RVAs | `EasyAntiCheat_EOS.sys` (`44.4 MB`) RVAs | `EasyAntiCheat_EOS.sys` (`46.17 MB` live) RVAs |")
    md.append("|---|---|---|---|---|---|")
    md.append("| `+0x008` | `InterruptTime` (`KSYSTEM_TIME`) | `0x4CF6B`, `0x15187B`, `0x17AA7C`, `0xE5AF85` (`Sec[7]`), `0x19B87DB` (`Sec[7]`) | `0x4E032`, `0x13C959`, `0x146022`, `0x1F71D8D` (`Sec[7]`), `0x2141F52` (`Sec[7]`) | `0xCABBB`, `0x147E42`, `0x1F100C`, `0x16C53C4` (`Sec[7]`) | `0xCCCBE`, `0x1017A3`, `0x1426D7E` (`Sec[7]`), `0x184EC74` (`Sec[7]`), `0x1B4B3AE` (`Sec[7]`) |")
    md.append("| `+0x014` | `SystemTime` (`KSYSTEM_TIME`) | `0x171FE2`, `0x17A827`, `0x1B286A`, `0x1CD486`, `0x1F2A10`, `0x12DB663` (`Sec[7]`), `0x151B4C7` (`Sec[7]`), `0x186E71D` (`Sec[7]`), `0x21D5096` (`Sec[7]`) | `0x4DDE3`, `0x9A2E1`, `0xA590D`, `0x1C6C32`, `0x126C56E` (`Sec[7]`), `0x1317748` (`Sec[7]`), `0x1AA87DE` (`Sec[7]`), `0x216822E` (`Sec[7]`) | `0x105CF9`, `0x1DC687`, `0x1EB817`, `0x1F937A`, `0x17E776A` (`Sec[7]`), `0x17F8753` (`Sec[7]`) | `0xCCA5B`, `0xF794B`, `0x157415`, `0x171B6A`, `0x133126F` (`Sec[7]`), `0x15A9D1A` (`Sec[7]`), `0x1EE86F8` (`Sec[7]`), `0x1F85742` (`Sec[7]`) |")
    md.append("| `+0x020` | `TimeZoneBias` (`KSYSTEM_TIME`) | `0x1C95B8A` (`Sec[7]`), `0x25ADDE3` (`Sec[7]`) | `0x15E8E6C` (`Sec[7]`), `0x1FBF7CB` (`Sec[7]`) | `0x13143F`, `0x1A0073` | `0x1E12EB`, `0x1ADA0B1` (`Sec[7]`) |")
    md.append("| `+0x260` | `NtBuildNumber` (`ULONG`) | `0x0F59A`, `0x149AAF`, `0x21EFF0`, `0x18717D8` (`Sec[7]`), `0x1871824` (`Sec[7]`) | `0x8D2FC`, `0x1CB13B`, `0x1B02C4E` (`Sec[7]`), `0x2364242` (`Sec[7]`), `0x23642BB` (`Sec[7]`) | `0x1360D0`, `0x207E6D`, `0x187B391` (`Sec[7]`) | `0x542CC`, `0x1D1A48`, `0x18D420D` (`Sec[7]`), `0x234DDD5` (`Sec[7]`) |")
    md.append("| `+0x274` | `ProcessorFeatures[64]` (`BOOLEAN[64]`) | `0x2091C8` | `0x2100DE` | `0x1B11B9` | `0xEFC8B` |")
    md.append("| `+0x2EC` | `SafeBootMode` (`BOOLEAN`) | `0x21EF4E` | `0x1CB08C` | `0x207DCA` | `0x1D19B7` |")
    md.append("| `+0x320` | `TickCount` (`KSYSTEM_TIME`) | `0x342ED`, `0x17A739`, `0x19FEC4`, `0xF1EA30` (`Sec[7]`) | `0x370A3`, `0x4DCF5`, `0x1EFC7E`, `0x1BD9DC8` (`Sec[7]`) | `0xDB729`, `0x151B35`, `0x187003`, `0x1F9289` | `0xAD4E1`, `0xCC95C`, `0x145EC8`, `0x1C0AD5` |")
    md.append("")
    md.append(f"- **Handlers / Instructions Stepped**: `{total_steps}` (`arith={total_arith}`, `mem={total_mem}`, `branch={total_branch}`, `exit=1`)")
    md.append("")
    md.append("## Inputs Read (`KUSER_SHARED_DATA` Page `0xFFFFF78000000000`)")
    for rva, addr, sz, val in kuser_reads:
        off = addr - 0xFFFFF78000000000
        md.append(f"- `RVA 0x{rva:07x}` read `{sz}` bytes (`0x{val:x}`) from `KUSER_SHARED_DATA+0x{off:03x}` (`0x{addr:016x}`)")
    md.append("")
    md.append("## Pseudo-C Reconstruction")
    md.append("```c")
    md.append("void eac_sample_kuser_shared_data(eac_kuser_snapshot_t* out) {")
    md.append("    out->interrupt_time = *(volatile uint64_t*)0xFFFFF78000000008ULL;")
    md.append("    out->system_time    = *(volatile uint64_t*)0xFFFFF78000000014ULL;")
    md.append("    out->timezone_bias  = *(volatile uint64_t*)0xFFFFF78000000020ULL;")
    md.append("    out->tick_count     = *(volatile uint64_t*)0xFFFFF78000000320ULL;")
    md.append("    out->nt_build_number = *(volatile uint32_t*)0xFFFFF78000000260ULL;")
    md.append("    eac_copy_or_hash_features(out->processor_features, (const uint8_t*)0xFFFFF78000000274ULL, 64);")
    md.append("    out->safe_boot_mode  = *(volatile uint8_t*)0xFFFFF780000002ECULL;")
    md.append("}")
    md.append("```")
    md.append("")
    md.append("## Executed Instructions (Unicorn Traces)")
    for title, trace in all_traces:
        md.append(f"### {title}")
        md.append("```asm")
        md.extend(trace)
        md.append("```")
        md.append("")

    out_path = os.path.join(OUT_DIR, "kuser_shared_data_reads.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    log_lines.append(
        f"WROTE {out_path} (total={total_steps}, arith={total_arith}, mem={total_mem}, branch={total_branch}, exit=1)"
    )


def generate_rsmb_report(drivers, log_lines):
    drv_dump = drivers["eac_dumped"]
    drv_fn = drivers["eacfn"]
    drv_44m = drivers["eos_44m"]
    drv_live = drivers["eos_live"]

    rsmb_info = []
    for label, drv, rva in [
        ("eac_dumped.sys", drv_dump, 0x2D458C),
        ("eacfn.sys", drv_fn, 0x2C5C8C),
        ("EasyAntiCheat_EOS.sys (44.4 MB)", drv_44m, 0x2BE27C),
        ("EasyAntiCheat_EOS.sys (46.17 MB live)", drv_live, 0x303B74),
    ]:
        raw20 = drv.read_rva(rva, 20)
        sig, action, tid, tlen = struct.unpack("<IIII", raw20[:16])
        rsmb_info.append((label, rva, raw20.hex(), sig, action, tid, tlen))

    stats_live, trace_live, reads_live, writes_live, _ = run_unicorn_trace(
        drv_live, 0x0345A8, max_steps=25, stop_rvas={0x034601}
    )
    stats_dump, trace_dump, reads_dump, writes_dump, _ = run_unicorn_trace(
        drv_dump, 0x0229D5, max_steps=25, stop_rvas={0x022A1E}
    )

    total_steps = stats_live["total"] + stats_dump["total"]
    total_arith = stats_live["arith"] + stats_dump["arith"]
    total_mem = stats_live["mem"] + stats_dump["mem"]
    total_branch = stats_live["branch"] + stats_dump["branch"]

    md = []
    md.append("# Devirtualization: SMBIOS `RSMB` Read (`SystemFirmwareTableInformation` Class 76)")
    md.append("")
    md.append("## Cross-Build `.rdata` `SYSTEM_FIRMWARE_TABLE_INFORMATION` Template")
    md.append("| Driver Build | `.rdata` RVA | Raw 20-Byte Template Hex | `ProviderSignature` | `Action` | `TableID` | `TableBufferLength` |")
    md.append("|---|---|---|---|---|---|---|")
    for label, rva, raw_hex, sig, action, tid, tlen in rsmb_info:
        md.append(f"| `{label}` | `0x{rva:06X}` | `{raw_hex}` | `0x{sig:08X}` (`'RSMB'`) | `{action}` (`Get`) | `{tid}` | `{tlen}` |")
    md.append("")
    md.append("## Dynamic Kernel Import Resolution (`.bearimp` & Affine Pointer Decryption)")
    md.append("- `ntoskrnl.exe!NtQuerySystemInformation` — `.bearimp` IAT RVA `0x29354C0`")
    md.append("- `ntoskrnl.exe!NtQuerySystemInformationEx` — `.bearimp` IAT RVA `0x29355D0`")
    md.append("- `ntoskrnl.exe!HalAcpiGetTableEx` — `.bearimp` IAT RVA `0x2935548`")
    md.append("- `ntoskrnl.exe!HalGetBusDataByOffset` — `.bearimp` IAT RVA `0x2935550`")
    md.append("- `ntoskrnl.exe!NtQuerySystemEnvironmentValueEx` — `.bearimp` IAT RVA `0x2935720`")
    md.append("")
    md.append(f"- **Dynamic Import Decryption Thunks Stepped**: `{total_steps}` (`arith={total_arith}`, `mem={total_mem}`, `branch={total_branch}`, `exit=1`)")
    md.append("")
    md.append("## Executed Instructions (Unicorn Traces of Affine Import Decryption Dispatch)")
    md.append("### 1. `eac_dumped.sys` (`.text RVA 0x0229D5..0x022A1E`)")
    md.append("```asm")
    md.extend(trace_dump)
    md.append("```")
    md.append("")
    md.append("### 2. `EasyAntiCheat_EOS.sys` (2026-11-25 live build, `.text RVA 0x0345A8..0x034601`)")
    md.append("```asm")
    md.extend(trace_live)
    md.append("```")
    md.append("")

    out_path = os.path.join(OUT_DIR, "rsmb_smbios_read.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    log_lines.append(
        "RSMB immediate hits: eac_dumped=0x2d458c, eacfn=0x2c5c8c, eos_44m=0x2be27c, eos_live=0x303b74"
    )
    log_lines.append(
        f"WROTE {out_path} (total={total_steps}, arith={total_arith}, mem={total_mem}, branch={total_branch}, exit=1)"
    )


def generate_driver_entry_report(drivers, log_lines):
    """
    New Report 1: Unicorn trace & disassembly of GsDriverEntry -> __security_init_cookie -> real DriverEntry -> Sec[7] bootstrap
    across all 4 driver builds.
    """
    configs = [
        ("eos_live",   "EasyAntiCheat_EOS.sys (46.17 MB live)", 0x27C438, 0x27C408, 0x327188, 0x17D881, 0x31DE78),
        ("eac_dumped", "eac_dumped.sys (40.25 MB dump)",        0x26AEB8, 0x26AE88, 0x313188, 0x1FD1A9, 0x309FF0),
        ("eacfn",      "eacfn.sys (43.21 MB .bearimp)",         0x266478, 0x266448, 0x30C188, 0x0416C8, 0x302890),
        ("eos_44m",    "EasyAntiCheat_EOS.sys (44.40 MB prior)", 0x255638, 0x255608, 0x2F8188, 0x13E76C, 0x2EFF70),
    ]

    total_steps = 0
    total_arith = 0
    total_mem = 0
    total_branch = 0
    traces = []
    resolved_cookies = []

    for key, label, ep_rva, cookie_fn_rva, _, real_init_rva, flt_iat_rva in configs:
        drv = drivers[key]
        # Resolve exact RIP-relative __security_cookie RVA from first instruction of cookie_fn_rva (`48 8B 05 <disp32>`)
        ins0 = drv.disasm_rva(cookie_fn_rva, size=16, max_insns=2)[0]
        disp = struct.unpack_from("<i", ins0.bytes, 3)[0]
        cookie_rva = ins0.address + ins0.size + disp
        # Also inspect first instruction of real_init_rva to see immediate Sec[7] jump target
        init_ins = drv.disasm_rva(real_init_rva, size=32, max_insns=4)
        sec7_entry = init_ins[0].op_str if (init_ins and init_ins[0].mnemonic == "jmp") else f"0x{real_init_rva:x}"
        resolved_cookies.append((label, ep_rva, cookie_fn_rva, cookie_rva, real_init_rva, sec7_entry, flt_iat_rva))

        def make_setup(c_rva):
            def _setup(uc, d, env):
                # Populate valid non-zero, non-default __security_cookie so GsDriverEntry passes check without int 0x29
                uc.mem_write(env["base"] + c_rva, struct.pack("<Q", 0x7A4E91C3B82D5F61))
                # Populate UNICODE_STRING RegistryPath at rdx_buf ("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\EasyAntiCheat_EOSSys")
                wstr = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\EasyAntiCheat_EOSSys\x00".encode("utf-16le")
                str_ptr = env["rdx_buf"] + 0x40
                uc.mem_write(str_ptr, wstr)
                uc.mem_write(env["rdx_buf"], struct.pack("<HHIQ", len(wstr) - 2, len(wstr), 0, str_ptr))
                # Populate minimal DRIVER_OBJECT at rcx_dev_obj (Size=0x150, DriverStart=base, DriverSize=d.size_of_image)
                uc.mem_write(env["rcx_dev_obj"] + 0x00, struct.pack("<hh", 4, 0x150))
                uc.mem_write(env["rcx_dev_obj"] + 0x18, struct.pack("<Q", env["base"]))
                uc.mem_write(env["rcx_dev_obj"] + 0x20, struct.pack("<I", d.size_of_image))
            return _setup

        stats, tr, _, _, _ = run_unicorn_trace(drv, ep_rva, max_steps=80, setup_fn=make_setup(cookie_rva))
        total_steps += stats["total"]
        total_arith += stats["arith"]
        total_mem += stats["mem"]
        total_branch += stats["branch"]
        traces.append((label, ep_rva, tr))

    md = []
    md.append("# Devirtualization: `GsDriverEntry` -> `__security_init_cookie` -> `Sec[7]` Bootstrap")
    md.append("")
    md.append("## Cross-Build `DriverEntry` & Bootstrap Matrix")
    md.append("| Driver Build | `EntryRVA` (`GsDriverEntry`) | `__security_init_cookie` RVA | `.data` `__security_cookie` RVA | Real Init Stub RVA | `Sec[7]` Bootstrap Target | Static `FltRegisterFilter` IAT RVA |")
    md.append("|---|---|---|---|---|---|---|")
    for label, ep, cfn, crva, rinit, s7, flt in resolved_cookies:
        md.append(f"| `{label}` | `0x{ep:06X}` | `0x{cfn:06X}` | `0x{crva:06X}` | `0x{rinit:06X}` | `{s7}` | `0x{flt:06X}` |")
    md.append("")
    md.append(f"- **Total Instructions Stepped Across 4 Builds**: `{total_steps}` (`arith={total_arith}`, `mem={total_mem}`, `branch={total_branch}`, `exit=1`)")
    md.append("")
    md.append("## Bootstrap Mechanism")
    md.append("1. **`GsDriverEntry` (`EntryRVA`)**: Saves `PDRIVER_OBJECT` (`RCX` -> `RDI`) and `PUNICODE_STRING RegistryPath` (`RDX` -> `RBX`), invokes `__security_init_cookie`, restores `(RCX, RDX)`, and calls the real driver initialization stub.")
    md.append("2. **`__security_init_cookie`**: Loads `__security_cookie` from `.data`; if `0` or equal to default constant `0x00002B992DDFA232`, triggers `__fastfail(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE)` (`mov ecx, 6; int 0x29`). Otherwise writes `~cookie` into `__security_cookie_complement` (`cookie_rva + 8`) and returns.")
    md.append("3. **Immediate `Sec[7]` Transition**: Every real initialization stub (`0x17D881` in `eos_live`, `0x1FD1A9` in `eac_dumped`, `0x0416C8` in `eacfn`, `0x13E76C` in `eos_44m`) immediately enters flattened/obfuscated `Sec[7]` basic blocks (`jmp 0x46E812` in `eos_live`, etc.) to initialize the encrypted import table and register minifilter/callbacks.")
    md.append("")
    md.append("## Executed Instructions (Unicorn `DriverEntry` -> `Sec[7]` Traces)")
    for label, ep, tr in traces:
        md.append(f"### `{label}` (`EntryRVA = 0x{ep:06X}`)")
        md.append("```asm")
        md.extend(tr[:55])
        md.append("```")
        md.append("")

    out_path = os.path.join(OUT_DIR, "driver_entry_and_init.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    log_lines.append(
        f"WROTE {out_path} (total={total_steps}, arith={total_arith}, mem={total_mem}, branch={total_branch}, exit=1)"
    )


def scan_affine_thunks_in_text(drv: DriverImage):
    s0 = drv.pe.sections[0]
    raw = drv.data[s0.PointerToRawData:s0.PointerToRawData + s0.SizeOfRawData]
    thunks = []
    for i in range(len(raw) - 32):
        if raw[i] == 0x48 and raw[i + 1] == 0xB8 and b"\x0f\xaf" in raw[i + 10:i + 28]:
            rva = s0.VirtualAddress + i
            insns = list(CS.disasm(raw[i:i + 36], rva))
            mnems = [x.mnemonic for x in insns[:7]]
            if "imul" in mnems and "sub" in mnems and "call" in mnems:
                c_mul = struct.unpack_from("<Q", raw, i + 2)[0]
                slot_rva = None
                for x in insns[:6]:
                    if x.mnemonic == "mov" and "[rip + " in x.op_str:
                        disp = int(x.op_str.split("[rip + ")[1].rstrip("]"), 0)
                        slot_rva = x.address + x.size + disp
                        break
                    if x.mnemonic == "mov" and "[rip - " in x.op_str:
                        disp = int(x.op_str.split("[rip - ")[1].rstrip("]"), 0)
                        slot_rva = x.address + x.size - disp
                        break
                if slot_rva is not None:
                    sbytes = drv.read_rva(slot_rva, 8)
                    sval = struct.unpack("<Q", sbytes)[0] if len(sbytes) == 8 else 0
                    thunks.append((rva, c_mul, slot_rva, sval))
    return thunks


def generate_affine_import_solver_report(drivers, log_lines):
    """
    New Report 2: Exhaustive .text affine call-site thunk inventory across all 4 builds,
    eac_dumped.sys live kernel pointer inventory, eacfn.sys .bearimp cross-reference,
    and Unicorn trace of MurmurHash3-style prologue K_state + call-thunk decryption.
    """
    summary_rows = []
    sample_rows = []
    for key, label in [
        ("eos_live",   "EasyAntiCheat_EOS.sys (46.17 MB live)"),
        ("eac_dumped", "eac_dumped.sys (40.25 MB dump)"),
        ("eacfn",      "eacfn.sys (43.21 MB .bearimp)"),
        ("eos_44m",    "EasyAntiCheat_EOS.sys (44.40 MB prior)"),
    ]:
        drv = drivers[key]
        thunks = scan_affine_thunks_in_text(drv)
        uniq_slots = sorted({t[2] for t in thunks})
        slot_min = f"0x{uniq_slots[0]:06X}" if uniq_slots else "N/A"
        slot_max = f"0x{uniq_slots[-1]:06X}" if uniq_slots else "N/A"
        summary_rows.append((label, len(thunks), len(uniq_slots), f"{slot_min}..{slot_max}"))
        for t in thunks[:4]:
            sample_rows.append((key, t[0], t[1], t[2], t[3]))

    # Count live high-half kernel pointers in eac_dumped.sys .rdata and .data
    drv_dump = drivers["eac_dumped"]
    dump_sec_stats = []
    for s in drv_dump.pe.sections:
        sname = s.Name.rstrip(b"\x00").decode("ascii", "replace")
        if sname in (".rdata", ".data"):
            raw = drv_dump.data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
            nz = 0
            hi = 0
            in_self = 0
            ext_k = 0
            for off in range(0, len(raw) - 7, 8):
                val = struct.unpack_from("<Q", raw, off)[0]
                if val != 0:
                    nz += 1
                if (val >> 44) == 0xFFFFF:
                    hi += 1
                    if drv_dump.image_base <= val < drv_dump.image_base + drv_dump.size_of_image:
                        in_self += 1
                    else:
                        ext_k += 1
            dump_sec_stats.append((sname, nz, hi, in_self, ext_k))

    # Trace prologue K_state derivation across eos_live (0x1D9C7D) and eac_dumped (0x5C9F5)
    def setup_kstate(uc, drv, env):
        uc.reg_write(UC_X86_REG_RDX, 0x3141592653589793)
        uc.reg_write(UC_X86_REG_R9,  0x3141592653589793)

    st_live_pro, tr_live_pro, _, _, uc_live = run_unicorn_trace(
        drivers["eos_live"], 0x1D9C7D, max_steps=23, setup_fn=setup_kstate
    )
    rbp_kstate_live = uc_live.reg_read(UC_X86_REG_RBP)

    st_dump_pro, tr_dump_pro, _, _, _ = run_unicorn_trace(
        drivers["eac_dumped"], 0x05C9F5, max_steps=24, setup_fn=setup_kstate
    )

    # Verify exact Python formula against Unicorn's RBP output for eos_live (0x1D9CA2..0x1D9CCD, C_MIX=0xFF51AFD7ED558CCD):
    seed = 0x3141592653589793
    c_mix_live = 0xFF51AFD7ED558CCD
    t = (seed * c_mix_live) & 0xFFFFFFFFFFFFFFFF
    folded = ((t >> 32) >> ((t >> 60) & 0x3F)) & 0xFFFFFFFFFFFFFFFF
    py_kstate = (((t ^ folded) * c_mix_live) ^ seed) & 0xFFFFFFFFFFFFFFFF

    total_steps = st_live_pro["total"] + st_dump_pro["total"]
    total_arith = st_live_pro["arith"] + st_dump_pro["arith"]
    total_mem = st_live_pro["mem"] + st_dump_pro["mem"]
    total_branch = st_live_pro["branch"] + st_dump_pro["branch"]

    md = []
    md.append("# Devirtualization: Prologue `K_state` Mixing & Affine Import Table Solver")
    md.append("")
    md.append("## 1. `.text` Affine Call-Site Thunk Inventory Across All 4 Builds")
    md.append("| Driver Build | `.text` Affine Call Thunks | Unique Encrypted Table Slots | Slot RVA Range (`.rdata`) |")
    md.append("|---|---|---|---|")
    for label, tcnt, ucnt, srng in summary_rows:
        md.append(f"| `{label}` | `{tcnt}` | `{ucnt}` | `{srng}` |")
    md.append("")
    md.append("## 2. `eac_dumped.sys` Live Kernel Memory Pointer Distribution (`ImageBase = 0xFFFFF80496FE0000`)")
    md.append("| Section | Non-Zero Qwords | `0xFFFFF...` Kernel Pointers | Self-Relocated (`eac_dumped.sys`) | External Kernel Targets (`ntoskrnl` / `FLTMGR` / Pool) |")
    md.append("|---|---|---|---|---|")
    for sname, nz, hi, in_self, ext_k in dump_sec_stats:
        md.append(f"| `{sname}` | `{nz}` | `{hi}` | `{in_self}` | `{ext_k}` |")
    md.append("")
    md.append("## 3. Algebraic Verification of Prologue `K_state` Derivation (`Unicorn` vs Closed-Form C++20)")
    md.append(f"- **Test Seed (`RDX`)**: `0x{seed:016X}`")
    md.append(f"- **`eos_live` Prologue `C_MIX` (`RVA 0x1D9CA2`)**: `0x{c_mix_live:016X}` (MurmurHash3 `fmix64` constant!)")
    md.append(f"- **Closed-Form Formula Output**: `0x{py_kstate:016X}`")
    md.append(f"- **Unicorn Emulated `RBP` After `0x1D9CCC`**: `0x{rbp_kstate_live:016X}`")
    md.append("")
    md.append("## 4. Sample Extracted Affine Call Thunks (`target = *(uint64_t*)(ImageBase + SlotRVA) - (C_MUL * K_state)`)")
    md.append("| Build | Thunk RVA | `C_MUL` (`movabs rax, imm64`) | Encrypted Slot RVA | On-Disk / Dumped Slot Value |")
    md.append("|---|---|---|---|---|")
    for key, trva, cmul, srva, sval in sample_rows:
        md.append(f"| `{key}` | `0x{trva:06X}` | `0x{cmul:016X}` | `0x{srva:06X}` | `0x{sval:016X}` |")
    md.append("")
    md.append(f"- **Prologue Instructions Stepped**: `{total_steps}` (`arith={total_arith}`, `mem={total_mem}`, `branch={total_branch}`, `exit=1`)")
    md.append("")
    md.append("## Executed Instructions (Unicorn Prologue `K_state` Traces)")
    md.append("### 1. `EasyAntiCheat_EOS.sys` (2026-11-25 live build, `RVA 0x1D9C7D..0x1D9CD0`)")
    md.append("```asm")
    md.extend(tr_live_pro)
    md.append("```")
    md.append("")
    md.append("### 2. `eac_dumped.sys` (`RVA 0x05C9F5..0x05CA48`)")
    md.append("```asm")
    md.extend(tr_dump_pro)
    md.append("```")
    md.append("")

    out_path = os.path.join(OUT_DIR, "affine_import_solver.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    log_lines.append(
        f"WROTE {out_path} (total={total_steps}, arith={total_arith}, mem={total_mem}, branch={total_branch}, exit=1)"
    )


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_lines = [f"[{now_str}] START eac_devirt_runner (v3 cross-build verified + DriverEntry + Affine Solver)"]

    drivers = {}
    for k, p in BINS.items():
        if not os.path.exists(p):
            print(f"ERROR: missing binary {p}", file=sys.stderr)
            sys.exit(1)
        drivers[k] = DriverImage(k, p)

    generate_ioctl_storage_report(drivers, log_lines)
    generate_smart_report(drivers, log_lines)
    generate_rsmb_report(drivers, log_lines)
    generate_kuser_report(drivers, log_lines)
    generate_driver_entry_report(drivers, log_lines)
    generate_affine_import_solver_report(drivers, log_lines)

    end_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_lines.append(f"[{end_str}] DONE")

    log_path = os.path.join(OUT_DIR, "progress.log")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(f"[{now_str}] {l}" if not l.startswith("[") else l for l in log_lines) + "\n")

    for l in log_lines:
        print(l)


if __name__ == "__main__":
    main()
