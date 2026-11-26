# Devirtualization: `GsDriverEntry` -> `__security_init_cookie` -> `Sec[7]` Bootstrap

## Cross-Build `DriverEntry` & Bootstrap Matrix
| Driver Build | `EntryRVA` (`GsDriverEntry`) | `__security_init_cookie` RVA | `.data` `__security_cookie` RVA | Real Init Stub RVA | `Sec[7]` Bootstrap Target | Static `FltRegisterFilter` IAT RVA |
|---|---|---|---|---|---|---|
| `EasyAntiCheat_EOS.sys (46.17 MB live)` | `0x27C438` | `0x27C408` | `0x327188` | `0x17D881` | `0x46e812` | `0x31DE78` |
| `eac_dumped.sys (40.25 MB dump)` | `0x26AEB8` | `0x26AE88` | `0x313188` | `0x1FD1A9` | `0x449896` | `0x309FF0` |
| `eacfn.sys (43.21 MB .bearimp)` | `0x266478` | `0x266448` | `0x30C218` | `0x0416C8` | `0x4449f3` | `0x302890` |
| `EasyAntiCheat_EOS.sys (44.40 MB prior)` | `0x255638` | `0x255608` | `0x2F8190` | `0x13E76C` | `0x403e73` | `0x2EFF70` |

- **Total Instructions Stepped Across 4 Builds**: `320` (`arith=42`, `mem=176`, `branch=44`, `exit=1`)

## Bootstrap Mechanism
1. **`GsDriverEntry` (`EntryRVA`)**: Saves `PDRIVER_OBJECT` (`RCX` -> `RDI`) and `PUNICODE_STRING RegistryPath` (`RDX` -> `RBX`), invokes `__security_init_cookie`, restores `(RCX, RDX)`, and calls the real driver initialization stub.
2. **`__security_init_cookie`**: Loads `__security_cookie` from `.data`; if `0` or equal to default constant `0x00002B992DDFA232`, triggers `__fastfail(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE)` (`mov ecx, 6; int 0x29`). Otherwise writes `~cookie` into `__security_cookie_complement` (`cookie_rva + 8`) and returns.
3. **Immediate `Sec[7]` Transition**: Every real initialization stub (`0x17D881` in `eos_live`, `0x1FD1A9` in `eac_dumped`, `0x0416C8` in `eacfn`, `0x13E76C` in `eos_44m`) immediately enters flattened/obfuscated `Sec[7]` basic blocks (`jmp 0x46E812` in `eos_live`, etc.) to initialize the encrypted import table and register minifilter/callbacks.

## Executed Instructions (Unicorn `DriverEntry` -> `Sec[7]` Traces)
### `EasyAntiCheat_EOS.sys (46.17 MB live)` (`EntryRVA = 0x27C438`)
```asm
RVA 0x027c438: 48895c2408               mov qword ptr [rsp + 8], rbx
RVA 0x027c43d: 57                       push rdi
RVA 0x027c43e: 4883ec20                 sub rsp, 0x20
RVA 0x027c442: 488bda                   mov rbx, rdx
RVA 0x027c445: 488bf9                   mov rdi, rcx
RVA 0x027c448: e8bbffffff               call 0x27c408
RVA 0x027c408: 488b0579ad0a00           mov rax, qword ptr [rip + 0xaad79]
RVA 0x027c40f: 4885c0                   test rax, rax
RVA 0x027c412: 741b                     je 0x27c42f
RVA 0x027c414: 48b932a2df2d992b0000     movabs rcx, 0x2b992ddfa232
RVA 0x027c41e: 483bc1                   cmp rax, rcx
RVA 0x027c421: 740c                     je 0x27c42f
RVA 0x027c423: 48f7d0                   not rax
RVA 0x027c426: 48890563ad0a00           mov qword ptr [rip + 0xaad63], rax
RVA 0x027c42d: c3                       ret 
RVA 0x027c44d: 488bd3                   mov rdx, rbx
RVA 0x027c450: 488bcf                   mov rcx, rdi
RVA 0x027c453: e82914f0ff               call 0x17d881
RVA 0x017d881: e98c0f2f00               jmp 0x46e812
RVA 0x046e812: 488da42440feffff         lea rsp, [rsp - 0x1c0]
RVA 0x046e81a: e844e8f1ff               call 0x38d063
RVA 0x038d063: 48894c2410               mov qword ptr [rsp + 0x10], rcx
RVA 0x038d068: 0f11542418               movups xmmword ptr [rsp + 0x18], xmm2
RVA 0x038d06d: 440f11642428             movups xmmword ptr [rsp + 0x28], xmm12
RVA 0x038d073: 4c89442438               mov qword ptr [rsp + 0x38], r8
RVA 0x038d078: 440f114c2440             movups xmmword ptr [rsp + 0x40], xmm9
RVA 0x038d07e: 4c89642450               mov qword ptr [rsp + 0x50], r12
RVA 0x038d083: 4c89742458               mov qword ptr [rsp + 0x58], r14
RVA 0x038d088: 0f115c2460               movups xmmword ptr [rsp + 0x60], xmm3
RVA 0x038d08d: 440f11442470             movups xmmword ptr [rsp + 0x70], xmm8
RVA 0x038d093: 0f11ac2480000000         movups xmmword ptr [rsp + 0x80], xmm5
RVA 0x038d09b: 4889b42490000000         mov qword ptr [rsp + 0x90], rsi
RVA 0x038d0a3: 50                       push rax
RVA 0x038d0a4: 9c                       pushfq 
RVA 0x038d0a5: 58                       pop rax
RVA 0x038d0a6: 48898424a0000000         mov qword ptr [rsp + 0xa0], rax
RVA 0x038d0ae: 58                       pop rax
RVA 0x038d0af: 440f11bc24a0000000       movups xmmword ptr [rsp + 0xa0], xmm15
RVA 0x038d0b8: 50                       push rax
RVA 0x038d0b9: 488d8424d0010000         lea rax, [rsp + 0x1d0]
RVA 0x038d0c1: 48898424b8000000         mov qword ptr [rsp + 0xb8], rax
RVA 0x038d0c9: 58                       pop rax
RVA 0x038d0ca: 0f11bc24b8000000         movups xmmword ptr [rsp + 0xb8], xmm7
RVA 0x038d0d2: e89a000000               call 0x38d171
RVA 0x038d171: 50                       push rax
RVA 0x038d172: 53                       push rbx
RVA 0x038d173: 48c7c0ec6cc7ff           mov rax, 0xffffffffffc76cec
RVA 0x038d17a: 488b5c2410               mov rbx, qword ptr [rsp + 0x10]
RVA 0x038d17f: 488d1c03                 lea rbx, [rbx + rax]
RVA 0x038d183: 48899c24e0000000         mov qword ptr [rsp + 0xe0], rbx
RVA 0x038d18b: 5b                       pop rbx
RVA 0x038d18c: 58                       pop rax
RVA 0x038d18d: c3                       ret 
RVA 0x038d0d7: 440f11b424d0000000       movups xmmword ptr [rsp + 0xd0], xmm14
RVA 0x038d0e0: 0f11b424e0000000         movups xmmword ptr [rsp + 0xe0], xmm6
```

### `eac_dumped.sys (40.25 MB dump)` (`EntryRVA = 0x26AEB8`)
```asm
RVA 0x026aeb8: 48895c2408               mov qword ptr [rsp + 8], rbx
RVA 0x026aebd: 57                       push rdi
RVA 0x026aebe: 4883ec20                 sub rsp, 0x20
RVA 0x026aec2: 488bda                   mov rbx, rdx
RVA 0x026aec5: 488bf9                   mov rdi, rcx
RVA 0x026aec8: e8bbffffff               call 0x26ae88
RVA 0x026ae88: 488b05f9820a00           mov rax, qword ptr [rip + 0xa82f9]
RVA 0x026ae8f: 4885c0                   test rax, rax
RVA 0x026ae92: 741b                     je 0x26aeaf
RVA 0x026ae94: 48b932a2df2d992b0000     movabs rcx, 0x2b992ddfa232
RVA 0x026ae9e: 483bc1                   cmp rax, rcx
RVA 0x026aea1: 740c                     je 0x26aeaf
RVA 0x026aea3: 48f7d0                   not rax
RVA 0x026aea6: 488905e3820a00           mov qword ptr [rip + 0xa82e3], rax
RVA 0x026aead: c3                       ret 
RVA 0x026aecd: 488bd3                   mov rdx, rbx
RVA 0x026aed0: 488bcf                   mov rcx, rdi
RVA 0x026aed3: e8d122f9ff               call 0x1fd1a9
RVA 0x01fd1a9: e9e8c62400               jmp 0x449896
RVA 0x0449896: 488da42440feffff         lea rsp, [rsp - 0x1c0]
RVA 0x044989e: e862f7f2ff               call 0x379005
RVA 0x0379005: 50                       push rax
RVA 0x0379006: 9c                       pushfq 
RVA 0x0379007: 58                       pop rax
RVA 0x0379008: 4889442410               mov qword ptr [rsp + 0x10], rax
RVA 0x037900d: 58                       pop rax
RVA 0x037900e: 440f116c2410             movups xmmword ptr [rsp + 0x10], xmm13
RVA 0x0379014: 4889442420               mov qword ptr [rsp + 0x20], rax
RVA 0x0379019: 0f114c2428               movups xmmword ptr [rsp + 0x28], xmm1
RVA 0x037901e: 4c89742438               mov qword ptr [rsp + 0x38], r14
RVA 0x0379023: 0f11442440               movups xmmword ptr [rsp + 0x40], xmm0
RVA 0x0379028: 4c89442450               mov qword ptr [rsp + 0x50], r8
RVA 0x037902d: 440f117c2458             movups xmmword ptr [rsp + 0x58], xmm15
RVA 0x0379033: e8d8000000               call 0x379110
RVA 0x0379110: 50                       push rax
RVA 0x0379111: 53                       push rbx
RVA 0x0379112: 48c7c0b99bc8ff           mov rax, 0xffffffffffc89bb9
RVA 0x0379119: 488b5c2410               mov rbx, qword ptr [rsp + 0x10]
RVA 0x037911e: 488d1c03                 lea rbx, [rbx + rax]
RVA 0x0379122: 48899c2480000000         mov qword ptr [rsp + 0x80], rbx
RVA 0x037912a: 5b                       pop rbx
RVA 0x037912b: 58                       pop rax
RVA 0x037912c: c3                       ret 
RVA 0x0379038: 4c89542470               mov qword ptr [rsp + 0x70], r10
RVA 0x037903d: 0f117c2478               movups xmmword ptr [rsp + 0x78], xmm7
RVA 0x0379042: 0f11a42488000000         movups xmmword ptr [rsp + 0x88], xmm4
RVA 0x037904a: 4c899c2498000000         mov qword ptr [rsp + 0x98], r11
RVA 0x0379052: 4c89ac24a0000000         mov qword ptr [rsp + 0xa0], r13
RVA 0x037905a: 4c898c24a8000000         mov qword ptr [rsp + 0xa8], r9
RVA 0x0379062: 440f118c24b0000000       movups xmmword ptr [rsp + 0xb0], xmm9
RVA 0x037906b: 440f119424c0000000       movups xmmword ptr [rsp + 0xc0], xmm10
RVA 0x0379074: 440f118424d0000000       movups xmmword ptr [rsp + 0xd0], xmm8
RVA 0x037907d: 0f11b424e0000000         movups xmmword ptr [rsp + 0xe0], xmm6
RVA 0x0379085: 0f119c24f0000000         movups xmmword ptr [rsp + 0xf0], xmm3
RVA 0x037908d: 4889b42400010000         mov qword ptr [rsp + 0x100], rsi
```

### `eacfn.sys (43.21 MB .bearimp)` (`EntryRVA = 0x266478`)
```asm
RVA 0x0266478: 48895c2408               mov qword ptr [rsp + 8], rbx
RVA 0x026647d: 57                       push rdi
RVA 0x026647e: 4883ec20                 sub rsp, 0x20
RVA 0x0266482: 488bda                   mov rbx, rdx
RVA 0x0266485: 488bf9                   mov rdi, rcx
RVA 0x0266488: e8bbffffff               call 0x266448
RVA 0x0266448: 488b05c95d0a00           mov rax, qword ptr [rip + 0xa5dc9]
RVA 0x026644f: 4885c0                   test rax, rax
RVA 0x0266452: 741b                     je 0x26646f
RVA 0x0266454: 48b932a2df2d992b0000     movabs rcx, 0x2b992ddfa232
RVA 0x026645e: 483bc1                   cmp rax, rcx
RVA 0x0266461: 740c                     je 0x26646f
RVA 0x0266463: 48f7d0                   not rax
RVA 0x0266466: 488905b35d0a00           mov qword ptr [rip + 0xa5db3], rax
RVA 0x026646d: c3                       ret 
RVA 0x026648d: 488bd3                   mov rdx, rbx
RVA 0x0266490: 488bcf                   mov rcx, rdi
RVA 0x0266493: e830b2ddff               call 0x416c8
RVA 0x00416c8: e926334000               jmp 0x4449f3
RVA 0x04449f3: 488da42440feffff         lea rsp, [rsp - 0x1c0]
RVA 0x04449fb: e80ae6f2ff               call 0x37300a
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
RVA 0x037305c: 48898c24a8000000         mov qword ptr [rsp + 0xa8], rcx
RVA 0x0373064: 0f11ac24b0000000         movups xmmword ptr [rsp + 0xb0], xmm5
RVA 0x037306c: 4889b424c0000000         mov qword ptr [rsp + 0xc0], rsi
RVA 0x0373074: 440f11b424c8000000       movups xmmword ptr [rsp + 0xc8], xmm14
RVA 0x037307d: 4c898c24d8000000         mov qword ptr [rsp + 0xd8], r9
RVA 0x0373085: 0f119424e0000000         movups xmmword ptr [rsp + 0xe0], xmm2
RVA 0x037308d: 440f118c24f0000000       movups xmmword ptr [rsp + 0xf0], xmm9
RVA 0x0373096: 0f11842400010000         movups xmmword ptr [rsp + 0x100], xmm0
RVA 0x037309e: 4c89842410010000         mov qword ptr [rsp + 0x110], r8
RVA 0x03730a6: 4889842418010000         mov qword ptr [rsp + 0x118], rax
RVA 0x03730ae: 440f11bc2420010000       movups xmmword ptr [rsp + 0x120], xmm15
```

### `EasyAntiCheat_EOS.sys (44.40 MB prior)` (`EntryRVA = 0x255638`)
```asm
RVA 0x0255638: 48895c2408               mov qword ptr [rsp + 8], rbx
RVA 0x025563d: 57                       push rdi
RVA 0x025563e: 4883ec20                 sub rsp, 0x20
RVA 0x0255642: 488bda                   mov rbx, rdx
RVA 0x0255645: 488bf9                   mov rdi, rcx
RVA 0x0255648: e8bbffffff               call 0x255608
RVA 0x0255608: 488b05812b0a00           mov rax, qword ptr [rip + 0xa2b81]
RVA 0x025560f: 4885c0                   test rax, rax
RVA 0x0255612: 741b                     je 0x25562f
RVA 0x0255614: 48b932a2df2d992b0000     movabs rcx, 0x2b992ddfa232
RVA 0x025561e: 483bc1                   cmp rax, rcx
RVA 0x0255621: 740c                     je 0x25562f
RVA 0x0255623: 48f7d0                   not rax
RVA 0x0255626: 4889056b2b0a00           mov qword ptr [rip + 0xa2b6b], rax
RVA 0x025562d: c3                       ret 
RVA 0x025564d: 488bd3                   mov rdx, rbx
RVA 0x0255650: 488bcf                   mov rcx, rdi
RVA 0x0255653: e81491eeff               call 0x13e76c
RVA 0x013e76c: e902572c00               jmp 0x403e73
RVA 0x0403e73: 488da42440feffff         lea rsp, [rsp - 0x1c0]
RVA 0x0403e7b: e80094f5ff               call 0x35d280
RVA 0x035d280: 4889742408               mov qword ptr [rsp + 8], rsi
RVA 0x035d285: 440f116c2410             movups xmmword ptr [rsp + 0x10], xmm13
RVA 0x035d28b: 4c894c2420               mov qword ptr [rsp + 0x20], r9
RVA 0x035d290: 4c897c2428               mov qword ptr [rsp + 0x28], r15
RVA 0x035d295: 440f114c2430             movups xmmword ptr [rsp + 0x30], xmm9
RVA 0x035d29b: 0f116c2440               movups xmmword ptr [rsp + 0x40], xmm5
RVA 0x035d2a0: 4c89642450               mov qword ptr [rsp + 0x50], r12
RVA 0x035d2a5: 0f115c2458               movups xmmword ptr [rsp + 0x58], xmm3
RVA 0x035d2aa: 50                       push rax
RVA 0x035d2ab: 488d8424d0010000         lea rax, [rsp + 0x1d0]
RVA 0x035d2b3: 4889442470               mov qword ptr [rsp + 0x70], rax
RVA 0x035d2b8: 58                       pop rax
RVA 0x035d2b9: 48895c2470               mov qword ptr [rsp + 0x70], rbx
RVA 0x035d2be: 0f11742478               movups xmmword ptr [rsp + 0x78], xmm6
RVA 0x035d2c3: 4889942488000000         mov qword ptr [rsp + 0x88], rdx
RVA 0x035d2cb: 4c89b42490000000         mov qword ptr [rsp + 0x90], r14
RVA 0x035d2d3: 4c89842498000000         mov qword ptr [rsp + 0x98], r8
RVA 0x035d2db: 4889ac24a0000000         mov qword ptr [rsp + 0xa0], rbp
RVA 0x035d2e3: 4c899c24a8000000         mov qword ptr [rsp + 0xa8], r11
RVA 0x035d2eb: 48898c24b0000000         mov qword ptr [rsp + 0xb0], rcx
RVA 0x035d2f3: e890000000               call 0x35d388
RVA 0x035d388: 50                       push rax
RVA 0x035d389: 53                       push rbx
RVA 0x035d38a: 48c7c0ba94caff           mov rax, 0xffffffffffca94ba
RVA 0x035d391: 488b5c2410               mov rbx, qword ptr [rsp + 0x10]
RVA 0x035d396: 488d1c03                 lea rbx, [rbx + rax]
RVA 0x035d39a: 48899c24d0000000         mov qword ptr [rsp + 0xd0], rbx
RVA 0x035d3a2: 5b                       pop rbx
RVA 0x035d3a3: 58                       pop rax
RVA 0x035d3a4: c3                       ret 
RVA 0x035d2f8: 4889bc24c0000000         mov qword ptr [rsp + 0xc0], rdi
RVA 0x035d300: 0f118c24c8000000         movups xmmword ptr [rsp + 0xc8], xmm1
RVA 0x035d308: 48898424d8000000         mov qword ptr [rsp + 0xd8], rax
RVA 0x035d310: 440f11bc24e0000000       movups xmmword ptr [rsp + 0xe0], xmm15
```
