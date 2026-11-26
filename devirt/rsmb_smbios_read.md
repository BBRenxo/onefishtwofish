# Devirtualization: SMBIOS `RSMB` Read (`SystemFirmwareTableInformation` Class 76)

## Cross-Build `.rdata` `SYSTEM_FIRMWARE_TABLE_INFORMATION` Template
| Driver Build | `.rdata` RVA | Raw 20-Byte Template Hex | `ProviderSignature` | `Action` | `TableID` | `TableBufferLength` |
|---|---|---|---|---|---|---|
| `eac_dumped.sys` | `0x2D458C` | `424d535201000000000000000000000000000000` | `0x52534D42` (`'RSMB'`) | `1` (`Get`) | `0` | `0` |
| `eacfn.sys` | `0x2C5C8C` | `424d535201000000000000000000000000000000` | `0x52534D42` (`'RSMB'`) | `1` (`Get`) | `0` | `0` |
| `EasyAntiCheat_EOS.sys (44.4 MB)` | `0x2BE27C` | `424d535201000000000000000000000000000000` | `0x52534D42` (`'RSMB'`) | `1` (`Get`) | `0` | `0` |
| `EasyAntiCheat_EOS.sys (46.17 MB live)` | `0x303B74` | `424d535201000000000000000000000000000000` | `0x52534D42` (`'RSMB'`) | `1` (`Get`) | `0` | `0` |

## Dynamic Kernel Import Resolution (`.bearimp` & Affine Pointer Decryption)
- `ntoskrnl.exe!NtQuerySystemInformation` — `.bearimp` IAT RVA `0x29354C0`
- `ntoskrnl.exe!NtQuerySystemInformationEx` — `.bearimp` IAT RVA `0x29355D0`
- `ntoskrnl.exe!HalAcpiGetTableEx` — `.bearimp` IAT RVA `0x2935548`
- `ntoskrnl.exe!HalGetBusDataByOffset` — `.bearimp` IAT RVA `0x2935550`
- `ntoskrnl.exe!NtQuerySystemEnvironmentValueEx` — `.bearimp` IAT RVA `0x2935720`

- **Dynamic Import Decryption Thunks Stepped**: `28` (`arith=11`, `mem=9`, `branch=0`, `exit=1`)

## Executed Instructions (Unicorn Traces of Affine Import Decryption Dispatch)
### 1. `eac_dumped.sys` (`.text RVA 0x0229D5..0x022A1E`)
```asm
RVA 0x00229d5: 48c1e908                 shr rcx, 8
RVA 0x00229d9: 4189f1                   mov r9d, esi
RVA 0x00229dc: 4181e1ffffff00           and r9d, 0xffffff
RVA 0x00229e3: 48c1ee18                 shr rsi, 0x18
RVA 0x00229e7: 49ba3d7879be5e585e2c     movabs r10, 0x2c5e585ebe79783d
RVA 0x00229f1: 4d0fafd7                 imul r10, r15
RVA 0x00229f5: 4c8b1d5cd52d00           mov r11, qword ptr [rip + 0x2dd55c]
RVA 0x00229fc: 4d29d3                   sub r11, r10
RVA 0x00229ff: 48895c2440               mov qword ptr [rsp + 0x40], rbx
RVA 0x0022a04: 4c89642438               mov qword ptr [rsp + 0x38], r12
RVA 0x0022a09: 4889442430               mov qword ptr [rsp + 0x30], rax
RVA 0x0022a0e: 48894c2428               mov qword ptr [rsp + 0x28], rcx
RVA 0x0022a13: 4c894c2420               mov qword ptr [rsp + 0x20], r9
RVA 0x0022a18: 4889f9                   mov rcx, rdi
RVA 0x0022a1b: 4989f1                   mov r9, rsi
```

### 2. `EasyAntiCheat_EOS.sys` (2026-11-25 live build, `.text RVA 0x0345A8..0x034601`)
```asm
RVA 0x00345a8: 8bac24c0070000           mov ebp, dword ptr [rsp + 0x7c0]
RVA 0x00345af: 48beffffffffffff0000     movabs rsi, 0xffffffffffff
RVA 0x00345b9: 48bf2d4068b759ceebb3     movabs rdi, 0xb3ebce59b768402d
RVA 0x00345c3: 48b8689edb28434742ee     movabs rax, 0xee42474328db9e68
RVA 0x00345cd: 490fafc6                 imul rax, r14
RVA 0x00345d1: 4831e8                   xor rax, rbp
RVA 0x00345d4: 48ba88510a38a30223f6     movabs rdx, 0xf62302a3380a5188
RVA 0x00345de: 4831c2                   xor rdx, rax
RVA 0x00345e1: 48b8f0a195248b5eeaa4     movabs rax, 0xa4ea5e8b2495a1f0
RVA 0x00345eb: 490fafc6                 imul rax, r14
RVA 0x00345ef: 4c8b05d2fb2d00           mov r8, qword ptr [rip + 0x2dfbd2]
RVA 0x00345f6: 4929c0                   sub r8, rax
RVA 0x00345f9: 488d8c2440070000         lea rcx, [rsp + 0x740]
```
