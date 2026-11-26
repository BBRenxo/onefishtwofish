# Devirtualization: Prologue `K_state` Mixing & Affine Import Table Solver

## 1. `.text` Affine Call-Site Thunk Inventory Across All 4 Builds
| Driver Build | `.text` Affine Call Thunks | Unique Encrypted Table Slots | Slot RVA Range (`.rdata`) |
|---|---|---|---|
| `EasyAntiCheat_EOS.sys (46.17 MB live)` | `954` | `908` | `0x313808..0x31C610` |
| `eac_dumped.sys (40.25 MB dump)` | `953` | `911` | `0x2FFA08..0x3088B8` |
| `eacfn.sys (43.21 MB .bearimp)` | `958` | `915` | `0x2F8370..0x300DF0` |
| `EasyAntiCheat_EOS.sys (44.40 MB prior)` | `955` | `913` | `0x2E6378..0x2EEF40` |

## 2. `eac_dumped.sys` Live Kernel Memory Pointer Distribution (`ImageBase = 0xFFFFF80496FE0000`)
| Section | Non-Zero Qwords | `0xFFFFF...` Kernel Pointers | Self-Relocated (`eac_dumped.sys`) | External Kernel Targets (`ntoskrnl` / `FLTMGR` / Pool) |
|---|---|---|---|---|
| `.rdata` | `79202` | `2187` | `1611` | `576` |
| `.data` | `6423` | `250` | `165` | `85` |

## 3. Algebraic Verification of Prologue `K_state` Derivation (`Unicorn` vs Closed-Form C++20)
- **Test Seed (`RDX`)**: `0x3141592653589793`
- **`eos_live` Prologue `C_MIX` (`RVA 0x1D9CA2`)**: `0xFF51AFD7ED558CCD` (MurmurHash3 `fmix64` constant!)
- **Closed-Form Formula Output**: `0x4F6A41A016546856`
- **Unicorn Emulated `RBP` After `0x1D9CCC`**: `0x4F6A41A016546856`

## 4. Sample Extracted Affine Call Thunks (`target = *(uint64_t*)(ImageBase + SlotRVA) - (C_MUL * K_state)`)
| Build | Thunk RVA | `C_MUL` (`movabs rax, imm64`) | Encrypted Slot RVA | On-Disk / Dumped Slot Value |
|---|---|---|---|---|
| `eos_live` | `0x00B6DB` | `0x2C5C27A2177C0E48` | `0x313808` | `0xC255D0635949F668` |
| `eos_live` | `0x00F373` | `0x29EC77C86AF25635` | `0x313828` | `0x19CC12A159C5FD71` |
| `eos_live` | `0x00F6F7` | `0x83669D48C56D8A79` | `0x313838` | `0xC25F5D21F5C07B0C` |
| `eos_live` | `0x00FA86` | `0x9C0851976F2012A5` | `0x313840` | `0xE27F2CE79CA35BFB` |
| `eac_dumped` | `0x00C069` | `0x8361B84288762BB3` | `0x2FFA10` | `0x4C5582F85DBD08E3` |
| `eac_dumped` | `0x00C172` | `0x39BC5BBD8118F8CC` | `0x2FFA08` | `0xA704907E7E2DE851` |
| `eac_dumped` | `0x00C1CF` | `0x8361B84288762BB3` | `0x2FFA10` | `0x4C5582F85DBD08E3` |
| `eac_dumped` | `0x00C249` | `0x8361B84288762BB3` | `0x2FFA10` | `0x4C5582F85DBD08E3` |
| `eacfn` | `0x00ADA1` | `0x6DE8549C7F5D3306` | `0x2F8370` | `0x9B5A5A4231E5E800` |
| `eacfn` | `0x00C778` | `0xACBBCD1752EA1E56` | `0x2F8380` | `0x6ABB109D692EA92E` |
| `eacfn` | `0x00C91D` | `0xC205D029254ADA29` | `0x2F8390` | `0x9B6E46F456ECDDE4` |
| `eacfn` | `0x00CB79` | `0xC4E7FF6A0E4E0C52` | `0x2F83A8` | `0x425E5C24607938A4` |
| `eos_44m` | `0x00C5AD` | `0x97122B8D898002BE` | `0x2E6378` | `0x140BE687E4B6551B` |
| `eos_44m` | `0x00C7FF` | `0xD2CCD5D4564FC2F9` | `0x2E6388` | `0x1B268C66722605A5` |
| `eos_44m` | `0x00C83B` | `0x5B3E44667D98D580` | `0x2E6390` | `0x83724DBC90497021` |
| `eos_44m` | `0x00E21E` | `0xBC038B1ED6532EF1` | `0x2E6440` | `0xD8DDA5600C623DB1` |

- **Prologue Instructions Stepped**: `47` (`arith=17`, `mem=4`, `branch=0`, `exit=1`)

## Executed Instructions (Unicorn Prologue `K_state` Traces)
### 1. `EasyAntiCheat_EOS.sys` (2026-11-25 live build, `RVA 0x1D9C7D..0x1D9CD0`)
```asm
RVA 0x01d9c7d: 4157                     push r15
RVA 0x01d9c7f: 4156                     push r14
RVA 0x01d9c81: 4155                     push r13
RVA 0x01d9c83: 4154                     push r12
RVA 0x01d9c85: 56                       push rsi
RVA 0x01d9c86: 57                       push rdi
RVA 0x01d9c87: 55                       push rbp
RVA 0x01d9c88: 53                       push rbx
RVA 0x01d9c89: 4881ec88030000           sub rsp, 0x388
RVA 0x01d9c90: 4889ce                   mov rsi, rcx
RVA 0x01d9c93: 8bbc24f8030000           mov edi, dword ptr [rsp + 0x3f8]
RVA 0x01d9c9a: 4c8b9c24f0030000         mov r11, qword ptr [rsp + 0x3f0]
RVA 0x01d9ca2: 48b8cd8c55edd7af51ff     movabs rax, 0xff51afd7ed558ccd
RVA 0x01d9cac: 4989d2                   mov r10, rdx
RVA 0x01d9caf: 4c0fafd0                 imul r10, rax
RVA 0x01d9cb3: 4c89d5                   mov rbp, r10
RVA 0x01d9cb6: 48c1ed20                 shr rbp, 0x20
RVA 0x01d9cba: 4c89d1                   mov rcx, r10
RVA 0x01d9cbd: 48c1e93c                 shr rcx, 0x3c
RVA 0x01d9cc1: 48d3ed                   shr rbp, cl
RVA 0x01d9cc4: 4c31d5                   xor rbp, r10
RVA 0x01d9cc7: 480fafe8                 imul rbp, rax
RVA 0x01d9ccb: 4831d5                   xor rbp, rdx
```

### 2. `eac_dumped.sys` (`RVA 0x05C9F5..0x05CA48`)
```asm
RVA 0x005c9f5: 4157                     push r15
RVA 0x005c9f7: 4156                     push r14
RVA 0x005c9f9: 4155                     push r13
RVA 0x005c9fb: 4154                     push r12
RVA 0x005c9fd: 56                       push rsi
RVA 0x005c9fe: 57                       push rdi
RVA 0x005c9ff: 55                       push rbp
RVA 0x005ca00: 53                       push rbx
RVA 0x005ca01: 4881ec78030000           sub rsp, 0x378
RVA 0x005ca08: 4989ca                   mov r10, rcx
RVA 0x005ca0b: 488bbc24e8030000         mov rdi, qword ptr [rsp + 0x3e8]
RVA 0x005ca13: 4c8b9c24e0030000         mov r11, qword ptr [rsp + 0x3e0]
RVA 0x005ca1b: 48b8b9e5e41c6d4758bf     movabs rax, 0xbf58476d1ce4e5b9
RVA 0x005ca25: 4889fe                   mov rsi, rdi
RVA 0x005ca28: 480faff0                 imul rsi, rax
RVA 0x005ca2c: 4989f4                   mov r12, rsi
RVA 0x005ca2f: 49c1ec20                 shr r12, 0x20
RVA 0x005ca33: 4889f1                   mov rcx, rsi
RVA 0x005ca36: 48c1e93c                 shr rcx, 0x3c
RVA 0x005ca3a: 49d3ec                   shr r12, cl
RVA 0x005ca3d: 4931f4                   xor r12, rsi
RVA 0x005ca40: 4c0fafe0                 imul r12, rax
RVA 0x005ca44: 4931fc                   xor r12, rdi
RVA 0x005ca47: 49c1e02c                 shl r8, 0x2c
```
