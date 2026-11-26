# Devirtualization: `IOCTL_STORAGE_QUERY_PROPERTY` (`0x2D1400`)

## Cross-Build Targets & Entry Points
| Build | Path | Size | ImageBase | Handler Entry RVA | `0x2D1400` Write RVA | `Sec[7]` Continuation RVA | Completion Callback RVA |
|---|---|---|---|---|---|---|---|
| `eac_dumped.sys` | `C:\Users\Administrator\Downloads\eac_dumped.sys` | `40,251,392` B | `0xFFFFF80496FE0000` | `0x153938` | `0x153995` | `0x394CEA` / `0x394CF1` -> `0x135950E` | `0x184960` |
| `eacfn.sys` | `C:\Users\Administrator\Downloads\eacfn.sys` | `43,213,824` B | `0xFFFFF80400000000` | `0x0B90A3` | `0x0B90FC` | `0x41D1D5` / `0x41D1DD` -> `0x121E832` | `0x215101` |
| `EasyAntiCheat_EOS.sys` (2026-11-25 live) | `C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys` | `46,171,808` B | `0x0000000140000000` | `0x2A57ECA` (`Sec[7]`) | `0x2A57F24` | `0x45748F` -> `0x21351B0` | `0x221EA9` |
| `EasyAntiCheat_EOS.sys` (44.4 MB prior) | `C:\Users\Administrator\Downloads\EasyAntiCheat_EOS.sys` | `44,398,752` B | `0x0000000140000000` | `MBA-encoded in Sec[7]` (`0` literal `0x2D1400` / `0x2800000000` immediates) | `MBA` | `Sec[7]` | `Sec[7]` |

- **Total Instructions Stepped Across Traces**: `149` (`arith=20`, `mem=111`, `branch=9`, `exit=1`)

## Notes & Architectural Mechanism
- In `eac_dumped.sys` and `eacfn.sys`, the `IOCTL_STORAGE_QUERY_PROPERTY` (`0x002D1400`) builder resides in `.text` (`RVA 0x153938` and `RVA 0xB90A3`) and jumps into `Sec[7]` (`RVA 0x394CEA` / `0x41D1D5`).
- In live `EasyAntiCheat_EOS.sys` (`46,171,808` bytes, `2026-11-25`), the entire handler resides inside `Sec[7]` at `RVA 0x2A57ECA` (`0x2D1400` write at `RVA 0x2A57F24`), jumping to `Sec[7]` dispatcher `RVA 0x45748F` -> `0x21351B0`.
- In prior `Downloads\EasyAntiCheat_EOS.sys` (`44,398,752` bytes), exhaustive byte-scanning across `.text` and `Sec[7]` confirms `0` literal `00 14 2D 00` or `0x2800000000` immediates: that build synthesizes `0x2D1400` via MBA arithmetic inside `Sec[7]` just like `0x7C088` at `RVA 0x8A3B36`.

## Inputs Read (Memory / Virtual Frame `r12`)
- `RVA 0x0153938` read `8` bytes (`0x140000000`) from `0x00007ff802010060`
- `RVA 0x015393d` read `8` bytes (`0x7ff802028000`) from `0x00007ff8020100f8`
- `RVA 0x0153945` read `4` bytes (`0x0`) from `0x00007ff802010120`
- `RVA 0x015394d` read `8` bytes (`0x7ff802020000`) from `0x00007ff802010158`
- `RVA 0x015395f` read `8` bytes (`0x588f3589ff11eb34`) from `0x00007ff802010150`
- `RVA 0x0153967` read `8` bytes (`0x7ff802024000`) from `0x00007ff802010188`
- `RVA 0x015396f` read `8` bytes (`0x7cf000007d100`) from `0x00000001402c605f`
- `RVA 0x015396f` read `8` bytes (`0x7cc000007ce00`) from `0x00000001402c6067`
- `RVA 0x0379729` read `8` bytes (`0x2`) from `0x00007ff80101ffe8`
- `RVA 0x037972f` read `8` bytes (`0x140000000`) from `0x00007ff80101fff0`
- `RVA 0x037983b` read `8` bytes (`0x14037975a`) from `0x00007ff80101fff0`
- `RVA 0x037984c` read `8` bytes (`0x0`) from `0x00007ff80101ffe0`
- `RVA 0x037984d` read `8` bytes (`0x140000000`) from `0x00007ff80101ffe8`
- `RVA 0x037984e` read `8` bytes (`0x14037975a`) from `0x00007ff80101fff0`
- `RVA 0x037982b` read `8` bytes (`0x140000000`) from `0x00007ff80101fff0`
- `RVA 0x0379831` read `8` bytes (`0x140394cf6`) from `0x00007ff80101fff8`
- `RVA 0x135950e` read `8` bytes (`0x140002bf1`) from `0x00007ff801020060`
- `RVA 0x1359513` read `8` bytes (`0x7ff801020200`) from `0x00007ff801020128`
- `RVA 0x2a57eca` read `8` bytes (`0x7ff802020000`) from `0x00007ff802010040`
- `RVA 0x2a57ecf` read `8` bytes (`0x55aa55aa55aa55aa`) from `0x00007ff802010080`
- `RVA 0x2a57ed7` read `8` bytes (`0x7ff802024000`) from `0x00007ff8020100a0`
- `RVA 0x2a57edf` read `8` bytes (`0x140000000`) from `0x00007ff8020100b8`
- `RVA 0x2a57ef1` read `8` bytes (`0xcec613add59df883`) from `0x00007ff802010048`
- `RVA 0x2a57ef6` read `4` bytes (`0x0`) from `0x00007ff8020100f0`
- `RVA 0x2a57efe` read `8` bytes (`0xe2000011e4000011`) from `0x00000001402d6b2d`
- `RVA 0x2a57efe` read `8` bytes (`0xde000011e0000011`) from `0x00000001402d6b35`
- `RVA 0x21351b0` read `8` bytes (`0x7ff802020000`) from `0x00007ff802010000`
- `RVA 0x21351da` read `8` bytes (`0x140000000`) from `0x00007ff8020100c0`

## Outputs Written (`STORAGE_PROPERTY_QUERY`, `IO_STACK_LOCATION`, `r12` Frame)
- `RVA 0x0153976` wrote `8` bytes (`0x7cf000007d100`) to `0x00007ff802020000`
- `RVA 0x0153976` wrote `8` bytes (`0x7cc000007ce00`) to `0x00007ff802020008`
- `RVA 0x0153979` wrote `4` bytes (`0x0`) to `0x00007ff802020010`
- `RVA 0x0153986` wrote `8` bytes (`0x2800000000`) to `0x00007ff802020014`
- `RVA 0x015398a` wrote `4` bytes (`0x200`) to `0x00007ff80202001c`
- `RVA 0x0153991` wrote `8` bytes (`0x4242424242424242`) to `0x00007ff802024020`
- `RVA 0x0153995` wrote `4` bytes (`0x2d1400`) to `0x00007ff802024030`
- `RVA 0x015399d` wrote `4` bytes (`0x1030`) to `0x00007ff802024028`
- `RVA 0x01539ac` wrote `8` bytes (`0x140184960`) to `0x00007ff802024008`
- `RVA 0x01539b0` wrote `8` bytes (`0x4242424242424242`) to `0x00007ff802010018`
- `RVA 0x01539b5` wrote `8` bytes (`0x7cf000007d100`) to `0x00007ff802010038`
- `RVA 0x01539b5` wrote `8` bytes (`0x7cc000007ce00`) to `0x00007ff802010040`
- `RVA 0x01539bb` wrote `8` bytes (`0x7ff802020000`) to `0x00007ff802010048`
- `RVA 0x01539c0` wrote `8` bytes (`0x1030`) to `0x00007ff8020100a0`
- `RVA 0x01539cc` wrote `8` bytes (`0x7ff802028000`) to `0x00007ff802010140`
- `RVA 0x01539d4` wrote `8` bytes (`0x7ff802020000`) to `0x00007ff802010160`
- `RVA 0x0394cf1` wrote `8` bytes (`0x140394cf6`) to `0x00007ff80101fff8`
- `RVA 0x0379727` wrote `8` bytes (`0x140000000`) to `0x00007ff80101fff0`
- `RVA 0x0379728` wrote `8` bytes (`0x2`) to `0x00007ff80101ffe8`
- `RVA 0x037972a` wrote `8` bytes (`0x2`) to `0x00007ff801020000`
- `RVA 0x0379730` wrote `8` bytes (`0x0`) to `0x00007ff801020008`
- `RVA 0x0379730` wrote `8` bytes (`0x0`) to `0x00007ff801020010`
- `RVA 0x0379736` wrote `8` bytes (`0x140000000`) to `0x00007ff801020018`
- `RVA 0x037973b` wrote `8` bytes (`0x0`) to `0x00007ff801020020`
- `RVA 0x037973b` wrote `8` bytes (`0x0`) to `0x00007ff801020028`
- `RVA 0x0379740` wrote `8` bytes (`0x0`) to `0x00007ff801020030`
- `RVA 0x0379745` wrote `8` bytes (`0x0`) to `0x00007ff801020038`
- `RVA 0x0379745` wrote `8` bytes (`0x0`) to `0x00007ff801020040`
- `RVA 0x037974a` wrote `8` bytes (`0x7ff802024000`) to `0x00007ff801020048`
- `RVA 0x037974f` wrote `8` bytes (`0x0`) to `0x00007ff801020050`
- `RVA 0x037974f` wrote `8` bytes (`0x0`) to `0x00007ff801020058`
- `RVA 0x0379755` wrote `8` bytes (`0x14037975a`) to `0x00007ff80101fff0`
- `RVA 0x0379832` wrote `8` bytes (`0x140000000`) to `0x00007ff80101ffe8`
- `RVA 0x0379833` wrote `8` bytes (`0x0`) to `0x00007ff80101ffe0`
- `RVA 0x0379844` wrote `8` bytes (`0x140002bf1`) to `0x00007ff801020060`

## Pseudo-C Reconstruction
```c
void eac_prepare_storage_query_property_irp(eac_vm_frame_t* r12) {
    uint8_t* image_base        = (uint8_t*)r12->image_base_60;
    void*    device_obj        = (void*)r12->device_obj_f8;
    uint32_t query_param       = r12->query_param_120;
    uint8_t* query_buf         = (uint8_t*)r12->query_buf_158;
    uint64_t obf_context_key   = 0x1ACD77CBBD53A976ULL ^ r12->seed_150;
    PIO_STACK_LOCATION irp_sp  = (PIO_STACK_LOCATION)r12->irp_sp_188;

    memcpy(query_buf, image_base + 0x2C605F, 16); // +0x2C25F9 eacfn, +0x2D6B2D live EOS
    *(uint32_t*)(query_buf + 0x10) = query_param;
    *(uint64_t*)(query_buf + 0x14) = 0x0000002800000000ULL;
    *(uint32_t*)(query_buf + 0x1C) = 0x00000200U;

    irp_sp->Parameters.DeviceIoControl.Type3InputBuffer   = (void*)obf_context_key;
    irp_sp->Parameters.DeviceIoControl.IoControlCode      = 0x002D1400U;
    irp_sp->Parameters.DeviceIoControl.OutputBufferLength = 0x00001030U;
    irp_sp->CompletionRoutine = (PIO_COMPLETION_ROUTINE)(image_base + 0x184960);
}
```

## Executed Instructions (Unicorn Traces)
### 1. `eac_dumped.sys` (`RVA 0x153938..0x1539E2` -> `Sec[7] RVA 0x394CF1 -> 0x135950E`)
```asm
RVA 0x0153938: 498b442460               mov rax, qword ptr [r12 + 0x60]
RVA 0x015393d: 498b8c24f8000000         mov rcx, qword ptr [r12 + 0xf8]
RVA 0x0153945: 418b942420010000         mov edx, dword ptr [r12 + 0x120]
RVA 0x015394d: 498bb42458010000         mov rsi, qword ptr [r12 + 0x158]
RVA 0x0153955: 48bf76a953bdcb77cd1a     movabs rdi, 0x1acd77cbbd53a976
RVA 0x015395f: 4933bc2450010000         xor rdi, qword ptr [r12 + 0x150]
RVA 0x0153967: 4d8b842488010000         mov r8, qword ptr [r12 + 0x188]
RVA 0x015396f: 0f10805f602c00           movups xmm0, xmmword ptr [rax + 0x2c605f]
RVA 0x0153976: 0f1106                   movups xmmword ptr [rsi], xmm0
RVA 0x0153979: 895610                   mov dword ptr [rsi + 0x10], edx
RVA 0x015397c: 48ba0000000028000000     movabs rdx, 0x2800000000
RVA 0x0153986: 48895614                 mov qword ptr [rsi + 0x14], rdx
RVA 0x015398a: c7461c00020000           mov dword ptr [rsi + 0x1c], 0x200
RVA 0x0153991: 49897820                 mov qword ptr [r8 + 0x20], rdi
RVA 0x0153995: 41c7403000142d00         mov dword ptr [r8 + 0x30], 0x2d1400
RVA 0x015399d: 41c7402830100000         mov dword ptr [r8 + 0x28], 0x1030
RVA 0x01539a5: 488d9060491800           lea rdx, [rax + 0x184960]
RVA 0x01539ac: 49895008                 mov qword ptr [r8 + 8], rdx
RVA 0x01539b0: 49897c2418               mov qword ptr [r12 + 0x18], rdi
RVA 0x01539b5: 410f11442438             movups xmmword ptr [r12 + 0x38], xmm0
RVA 0x01539bb: 4989742448               mov qword ptr [r12 + 0x48], rsi
RVA 0x01539c0: 49c78424a000000030100000 mov qword ptr [r12 + 0xa0], 0x1030
RVA 0x01539cc: 49898c2440010000         mov qword ptr [r12 + 0x140], rcx
RVA 0x01539d4: 4989b42460010000         mov qword ptr [r12 + 0x160], rsi
RVA 0x01539dc: 4805ea4c3900             add rax, 0x394cea
RVA 0x01539e2: ffe0                     jmp rax
; --- Sec[7] Continuation (RVA 0x394CF1 -> 0x135950E) ---
RVA 0x0394cf1: e8314afeff               call 0x379727
RVA 0x0379727: 50                       push rax
RVA 0x0379728: 9c                       pushfq 
RVA 0x0379729: 58                       pop rax
RVA 0x037972a: 4889442410               mov qword ptr [rsp + 0x10], rax
RVA 0x037972f: 58                       pop rax
RVA 0x0379730: 440f116c2410             movups xmmword ptr [rsp + 0x10], xmm13
RVA 0x0379736: 4889442420               mov qword ptr [rsp + 0x20], rax
RVA 0x037973b: 0f114c2428               movups xmmword ptr [rsp + 0x28], xmm1
RVA 0x0379740: 4c89742438               mov qword ptr [rsp + 0x38], r14
RVA 0x0379745: 0f11442440               movups xmmword ptr [rsp + 0x40], xmm0
RVA 0x037974a: 4c89442450               mov qword ptr [rsp + 0x50], r8
RVA 0x037974f: 440f117c2458             movups xmmword ptr [rsp + 0x58], xmm15
RVA 0x0379755: e8d8000000               call 0x379832
RVA 0x0379832: 50                       push rax
RVA 0x0379833: 53                       push rbx
RVA 0x0379834: 48c7c09794c8ff           mov rax, 0xffffffffffc89497
RVA 0x037983b: 488b5c2410               mov rbx, qword ptr [rsp + 0x10]
RVA 0x0379840: 488d1c03                 lea rbx, [rbx + rax]
RVA 0x0379844: 48899c2480000000         mov qword ptr [rsp + 0x80], rbx
RVA 0x037984c: 5b                       pop rbx
RVA 0x037984d: 58                       pop rax
RVA 0x037984e: c3                       ret 
RVA 0x037975a: 4c89542470               mov qword ptr [rsp + 0x70], r10
RVA 0x037975f: 0f117c2478               movups xmmword ptr [rsp + 0x78], xmm7
RVA 0x0379764: 0f11a42488000000         movups xmmword ptr [rsp + 0x88], xmm4
RVA 0x037976c: 4c899c2498000000         mov qword ptr [rsp + 0x98], r11
RVA 0x0379774: 4c89ac24a0000000         mov qword ptr [rsp + 0xa0], r13
RVA 0x037977c: 4c898c24a8000000         mov qword ptr [rsp + 0xa8], r9
RVA 0x0379784: 440f118c24b0000000       movups xmmword ptr [rsp + 0xb0], xmm9
RVA 0x037978d: 440f119424c0000000       movups xmmword ptr [rsp + 0xc0], xmm10
RVA 0x0379796: 440f118424d0000000       movups xmmword ptr [rsp + 0xd0], xmm8
RVA 0x037979f: 0f11b424e0000000         movups xmmword ptr [rsp + 0xe0], xmm6
RVA 0x03797a7: 0f119c24f0000000         movups xmmword ptr [rsp + 0xf0], xmm3
RVA 0x03797af: 4889b42400010000         mov qword ptr [rsp + 0x100], rsi
RVA 0x03797b7: 0f11942408010000         movups xmmword ptr [rsp + 0x108], xmm2
RVA 0x03797bf: 440f119c2418010000       movups xmmword ptr [rsp + 0x118], xmm11
RVA 0x03797c8: 4c89a42428010000         mov qword ptr [rsp + 0x128], r12
RVA 0x03797d0: 4889ac2430010000         mov qword ptr [rsp + 0x130], rbp
RVA 0x03797d8: 0f11ac2438010000         movups xmmword ptr [rsp + 0x138], xmm5
RVA 0x03797e0: 4889942448010000         mov qword ptr [rsp + 0x148], rdx
RVA 0x03797e8: 4889bc2450010000         mov qword ptr [rsp + 0x150], rdi
RVA 0x03797f0: 48899c2458010000         mov qword ptr [rsp + 0x158], rbx
RVA 0x03797f8: 4c89bc2460010000         mov qword ptr [rsp + 0x160], r15
RVA 0x0379800: 48898c2468010000         mov qword ptr [rsp + 0x168], rcx
RVA 0x0379808: 440f11b42470010000       movups xmmword ptr [rsp + 0x170], xmm14
RVA 0x0379811: 440f11a42480010000       movups xmmword ptr [rsp + 0x180], xmm12
RVA 0x037981a: 50                       push rax
RVA 0x037981b: 488d8424d0010000         lea rax, [rsp + 0x1d0]
RVA 0x0379823: 4889842498010000         mov qword ptr [rsp + 0x198], rax
RVA 0x037982b: 58                       pop rax
RVA 0x037982c: 4c8d642408               lea r12, [rsp + 8]
RVA 0x0379831: c3                       ret 
RVA 0x0394cf6: 4883e4f0                 and rsp, 0xfffffffffffffff0
RVA 0x0394cfa: 4883ec08                 sub rsp, 8
RVA 0x0394cfe: e90b48fc00               jmp 0x135950e
RVA 0x135950e: 498b442460               mov rax, qword ptr [r12 + 0x60]
RVA 0x1359513: 498b8c2428010000         mov rcx, qword ptr [r12 + 0x128]
RVA 0x135951b: 4883c130                 add rcx, 0x30
RVA 0x135951f: 488d9021c43a00           lea rdx, [rax + 0x3ac421]
```

### 2. `eacfn.sys` (`RVA 0x0B90A3..0x0B9152` -> `Sec[7] RVA 0x41D1DD -> 0x121E832`)
```asm
RVA 0x00b90a3: 498b0424                 mov rax, qword ptr [r12]
RVA 0x00b90a7: 418b4c2458               mov ecx, dword ptr [r12 + 0x58]
RVA 0x00b90ac: 498b9424b8000000         mov rdx, qword ptr [r12 + 0xb8]
RVA 0x00b90b4: 498bb42428010000         mov rsi, qword ptr [r12 + 0x128]
RVA 0x00b90bc: 48bfe76e5aa854465927     movabs rdi, 0x27594654a85a6ee7
RVA 0x00b90c6: 4933bc2450010000         xor rdi, qword ptr [r12 + 0x150]
RVA 0x00b90ce: 4d8b842468010000         mov r8, qword ptr [r12 + 0x168]
RVA 0x00b90d6: 0f1080f9252c00           movups xmm0, xmmword ptr [rax + 0x2c25f9]
RVA 0x00b90dd: 0f1106                   movups xmmword ptr [rsi], xmm0
RVA 0x00b90e0: 894e10                   mov dword ptr [rsi + 0x10], ecx
RVA 0x00b90e3: 48b90000000028000000     movabs rcx, 0x2800000000
RVA 0x00b90ed: 48894e14                 mov qword ptr [rsi + 0x14], rcx
RVA 0x00b90f1: c7461c00020000           mov dword ptr [rsi + 0x1c], 0x200
RVA 0x00b90f8: 49897828                 mov qword ptr [r8 + 0x28], rdi
RVA 0x00b90fc: 41c7403000142d00         mov dword ptr [r8 + 0x30], 0x2d1400
RVA 0x00b9104: 41c7402030100000         mov dword ptr [r8 + 0x20], 0x1030
RVA 0x00b910c: 488d8801512100           lea rcx, [rax + 0x215101]
RVA 0x00b9113: 49894808                 mov qword ptr [r8 + 8], rcx
RVA 0x00b9117: 4989942488000000         mov qword ptr [r12 + 0x88], rdx
RVA 0x00b911f: 4989b424a0000000         mov qword ptr [r12 + 0xa0], rsi
RVA 0x00b9127: 4989b424d0000000         mov qword ptr [r12 + 0xd0], rsi
RVA 0x00b912f: 410f118424f8000000       movups xmmword ptr [r12 + 0xf8], xmm0
RVA 0x00b9138: 49c784240801000030100000 mov qword ptr [r12 + 0x108], 0x1030
RVA 0x00b9144: 4989bc2410010000         mov qword ptr [r12 + 0x110], rdi
RVA 0x00b914c: 4805d5d14100             add rax, 0x41d1d5
RVA 0x00b9152: ffe0                     jmp rax
; --- Sec[7] Continuation (RVA 0x41D1DD -> 0x121E832) ---
RVA 0x041d1dd: 488da42440feffff         lea rsp, [rsp - 0x1c0]
RVA 0x041d1e5: e8205ef5ff               call 0x37300a
RVA 0x037300a: e806010000               call 0x373115
RVA 0x0373115: 50                       push rax
RVA 0x0373116: 53                       push rbx
RVA 0x0373117: 48c7c058fbc8ff           mov rax, 0xffffffffffc8fb58
RVA 0x037311e: 488b5c2410               mov rbx, qword ptr [rsp + 0x10]
RVA 0x0373123: 488d1c03                 lea rbx, [rbx + rax]
RVA 0x0373127: 48895c2420               mov qword ptr [rsp + 0x20], rbx
RVA 0x037312c: 5b                       pop rbx
RVA 0x037312d: 58                       pop rax
RVA 0x037312e: c3                       ret 
RVA 0x037300f: 440f11642410             movups xmmword ptr [rsp + 0x10], xmm12
RVA 0x0373015: 4c895c2420               mov qword ptr [rsp + 0x20], r11
RVA 0x037301a: 4c89742428               mov qword ptr [rsp + 0x28], r14
RVA 0x037301f: 0f117c2430               movups xmmword ptr [rsp + 0x30], xmm7
RVA 0x0373024: 440f11442440             movups xmmword ptr [rsp + 0x40], xmm8
RVA 0x037302a: 4c89542450               mov qword ptr [rsp + 0x50], r10
RVA 0x037302f: 48897c2458               mov qword ptr [rsp + 0x58], rdi
RVA 0x0373034: 4c89642460               mov qword ptr [rsp + 0x60], r12
RVA 0x0373039: 48896c2468               mov qword ptr [rsp + 0x68], rbp
RVA 0x037303e: 440f11542470             movups xmmword ptr [rsp + 0x70], xmm10
RVA 0x0373044: 0f11b42480000000         movups xmmword ptr [rsp + 0x80], xmm6
RVA 0x037304c: 4889942490000000         mov qword ptr [rsp + 0x90], rdx
RVA 0x0373054: 0f119c2498000000         movups xmmword ptr [rsp + 0x98], xmm3
```

### 3. `EasyAntiCheat_EOS.sys` (2026-11-25 live build, `Sec[7] RVA 0x2A57ECA..0x2A57F71 -> 0x45748F -> 0x21351B0`)
```asm
RVA 0x2a57eca: 498b4c2440               mov rcx, qword ptr [r12 + 0x40]
RVA 0x2a57ecf: 498b942480000000         mov rdx, qword ptr [r12 + 0x80]
RVA 0x2a57ed7: 498bb424a0000000         mov rsi, qword ptr [r12 + 0xa0]
RVA 0x2a57edf: 498b8424b8000000         mov rax, qword ptr [r12 + 0xb8]
RVA 0x2a57ee7: 48bf29ad378007466c9b     movabs rdi, 0x9b6c46078037ad29
RVA 0x2a57ef1: 49337c2448               xor rdi, qword ptr [r12 + 0x48]
RVA 0x2a57ef6: 418b9c24f0000000         mov ebx, dword ptr [r12 + 0xf0]
RVA 0x2a57efe: 0f10802d6b2d00           movups xmm0, xmmword ptr [rax + 0x2d6b2d]
RVA 0x2a57f05: 0f1101                   movups xmmword ptr [rcx], xmm0
RVA 0x2a57f08: 895910                   mov dword ptr [rcx + 0x10], ebx
RVA 0x2a57f0b: 49b80000000028000000     movabs r8, 0x2800000000
RVA 0x2a57f15: 4c894114                 mov qword ptr [rcx + 0x14], r8
RVA 0x2a57f19: c7411c00020000           mov dword ptr [rcx + 0x1c], 0x200
RVA 0x2a57f20: 48895620                 mov qword ptr [rsi + 0x20], rdx
RVA 0x2a57f24: c7463000142d00           mov dword ptr [rsi + 0x30], 0x2d1400
RVA 0x2a57f2b: c7462830100000           mov dword ptr [rsi + 0x28], 0x1030
RVA 0x2a57f32: 488d90a91e2200           lea rdx, [rax + 0x221ea9]
RVA 0x2a57f39: 48895608                 mov qword ptr [rsi + 8], rdx
RVA 0x2a57f3d: 49890c24                 mov qword ptr [r12], rcx
RVA 0x2a57f41: 49897c2428               mov qword ptr [r12 + 0x28], rdi
RVA 0x2a57f46: 49c78424e000000030100000 mov qword ptr [r12 + 0xe0], 0x1030
RVA 0x2a57f52: 4d898424e8000000         mov qword ptr [r12 + 0xe8], r8
RVA 0x2a57f5a: 410f11842458010000       movups xmmword ptr [r12 + 0x158], xmm0
RVA 0x2a57f63: 49898c2468010000         mov qword ptr [r12 + 0x168], rcx
RVA 0x2a57f6b: 48058f744500             add rax, 0x45748f
RVA 0x2a57f71: ffe0                     jmp rax
RVA 0x045748f: e91cddcd01               jmp 0x21351b0
RVA 0x21351b0: 498b0424                 mov rax, qword ptr [r12]
RVA 0x21351b4: 48b9320f7c931db1411d     movabs rcx, 0x1d41b11d937c0f32
RVA 0x21351be: 4801c1                   add rcx, rax
RVA 0x21351c1: 49890c24                 mov qword ptr [r12], rcx
RVA 0x21351c5: 48bab314c030ee56659b     movabs rdx, 0x9b6556ee30c014b3
RVA 0x21351cf: 4801c2                   add rdx, rax
RVA 0x21351d2: 4989942498010000         mov qword ptr [r12 + 0x198], rdx
RVA 0x21351da: 49038c24c0000000         add rcx, qword ptr [r12 + 0xc0]
RVA 0x21351e2: 48b8b78bb5351e6bf141     movabs rax, 0x41f16b1e35b58bb7
RVA 0x21351ec: 4801c8                   add rax, rcx
```
