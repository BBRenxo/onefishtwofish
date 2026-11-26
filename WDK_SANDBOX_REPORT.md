# C++20 Unicorn x86_64 WDM Kernel Driver Sandbox Report (`wdk_sandbox`)

## WDM Kernel Driver Sandbox Emulation (`wdk_sandbox` — C++20 + Unicorn x86_64)

Full PE64 image mapping at `0x0000000140000000` with `IMAGE_REL_BASED_DIR64` base relocation rebasing, `LOAD_CONFIG` `__security_cookie` pre-initialization, synthesized `_DRIVER_OBJECT` (`RCX`), `_UNICODE_STRING RegistryPath` (`RDX`), `GS_BASE` (`_KPCR` / `_KPRCB` / `_KTHREAD` / `_EPROCESS`), `KUSER_SHARED_DATA` (`0xFFFFF78000000000`), `CPUID` bare-metal interception, and `.bearimp` / IAT kernel API trampolines.

| Target | `StartRVA` | `LastRVA` | Insns Executed | `.text` Insns | `Sec[7]` Insns | Basic Blocks | Relocs Applied | Auto-Mapped Pages | `KUSER` Reads | `CPUID` Traps | Stub Calls | Stop Reason |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `eos_live` | `0x27C438` | `0x1B363BB` | `100000` | `754` | `99246` | `1010` | `0` | `0` | `2` | `0` | `0` | `instruction_budget_reached` |
| `eac_dumped` | `0x26AEB8` | `0x85EE5B` | `100000` | `297` | `99703` | `1006` | `6276` | `1` | `2` | `0` | `0` | `instruction_budget_reached` |
| `eacfn` | `0x266478` | `0x188AEEE` | `100000` | `397` | `99603` | `1021` | `6036` | `1` | `2` | `0` | `0` | `instruction_budget_reached` |
| `eos_prior` | `0x255638` | `0x118B51E` | `100000` | `307` | `99693` | `998` | `0` | `0` | `2` | `0` | `0` | `instruction_budget_reached` |
| `eos_live:cpuid_leaf` | `0xFD37` | `0x27C3C4` | `32` | `32` | `0` | `7` | `0` | `0` | `0` | `1` | `0` | `instruction_budget_reached` |
| `eos_live:kuser_2ec` | `0x1D19B7` | `0x1D19C3` | `3` | `3` | `0` | `1` | `0` | `0` | `1` | `0` | `0` | `completed_within_budget` |

### Sandbox Run: `eos_live` (`C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys`)

#### Sample Execution Trace (`GsDriverEntry` -> `Sec[7]` Transition)

```text
step=   1 RVA=0x027C438 [.text]  48895c2408
step=   2 RVA=0x027C43D [.text]  57
step=   3 RVA=0x027C43E [.text]  4883ec20
step=   4 RVA=0x027C442 [.text]  488bda
step=   5 RVA=0x027C445 [.text]  488bf9
step=   6 RVA=0x027C448 [.text]  e8bbffffff
step=   7 RVA=0x027C408 [.text]  488b0579ad0a00
step=   8 RVA=0x027C40F [.text]  4885c0
step=   9 RVA=0x027C412 [.text]  741b
step=  10 RVA=0x027C414 [.text]  48b932a2df2d992b0000
step=  11 RVA=0x027C41E [.text]  483bc1
step=  12 RVA=0x027C421 [.text]  740c
step=  13 RVA=0x027C423 [.text]  48f7d0
step=  14 RVA=0x027C426 [.text]  48890563ad0a00
step=  15 RVA=0x027C42D [.text]  c3
step=  16 RVA=0x027C44D [.text]  488bd3
step=  17 RVA=0x027C450 [.text]  488bcf
step=  18 RVA=0x027C453 [.text]  e82914f0ff
step=  19 RVA=0x017D881 [.text]  e98c0f2f00
step=  20 RVA=0x046E812 [Sec[7]] 488da42440feffff
step=  21 RVA=0x046E81A [Sec[7]] e844e8f1ff
step=  22 RVA=0x038D063 [Sec[7]] 48894c2410
step=  23 RVA=0x038D068 [Sec[7]] 0f11542418
step=  24 RVA=0x038D06D [Sec[7]] 440f11642428
step=  25 RVA=0x038D073 [Sec[7]] 4c89442438
step=  26 RVA=0x038D078 [Sec[7]] 440f114c2440
step=  27 RVA=0x038D07E [Sec[7]] 4c89642450
step=  28 RVA=0x038D083 [Sec[7]] 4c89742458
step=  29 RVA=0x038D088 [Sec[7]] 0f115c2460
step=  30 RVA=0x038D08D [Sec[7]] 440f11442470
step=  31 RVA=0x038D093 [Sec[7]] 0f11ac2480000000
step=  32 RVA=0x038D09B [Sec[7]] 4889b42490000000
step=  33 RVA=0x038D0A3 [Sec[7]] 50
step=  34 RVA=0x038D0A4 [Sec[7]] 9c
step=  35 RVA=0x038D0A5 [Sec[7]] 58
step=  36 RVA=0x038D0A6 [Sec[7]] 48898424a0000000
step=  37 RVA=0x038D0AE [Sec[7]] 58
step=  38 RVA=0x038D0AF [Sec[7]] 440f11bc24a0000000
step=  39 RVA=0x038D0B8 [Sec[7]] 50
step=  40 RVA=0x038D0B9 [Sec[7]] 488d8424d0010000
step=  41 RVA=0x038D0C1 [Sec[7]] 48898424b8000000
step=  42 RVA=0x038D0C9 [Sec[7]] 58
step=  43 RVA=0x038D0CA [Sec[7]] 0f11bc24b8000000
```

### Sandbox Run: `eac_dumped` (`C:\Users\Administrator\Downloads\eac_dumped.sys`)

#### Sample Execution Trace (`GsDriverEntry` -> `Sec[7]` Transition)

```text
step=   1 RVA=0x026AEB8 [.text]  48895c2408
step=   2 RVA=0x026AEBD [.text]  57
step=   3 RVA=0x026AEBE [.text]  4883ec20
step=   4 RVA=0x026AEC2 [.text]  488bda
step=   5 RVA=0x026AEC5 [.text]  488bf9
step=   6 RVA=0x026AEC8 [.text]  e8bbffffff
step=   7 RVA=0x026AE88 [.text]  488b05f9820a00
step=   8 RVA=0x026AE8F [.text]  4885c0
step=   9 RVA=0x026AE92 [.text]  741b
step=  10 RVA=0x026AE94 [.text]  48b932a2df2d992b0000
step=  11 RVA=0x026AE9E [.text]  483bc1
step=  12 RVA=0x026AEA1 [.text]  740c
step=  13 RVA=0x026AEA3 [.text]  48f7d0
step=  14 RVA=0x026AEA6 [.text]  488905e3820a00
step=  15 RVA=0x026AEAD [.text]  c3
step=  16 RVA=0x026AECD [.text]  488bd3
step=  17 RVA=0x026AED0 [.text]  488bcf
step=  18 RVA=0x026AED3 [.text]  e8d122f9ff
step=  19 RVA=0x01FD1A9 [.text]  e9e8c62400
step=  20 RVA=0x0449896 [Sec[7]] 488da42440feffff
step=  21 RVA=0x044989E [Sec[7]] e862f7f2ff
step=  22 RVA=0x0379005 [Sec[7]] 50
step=  23 RVA=0x0379006 [Sec[7]] 9c
step=  24 RVA=0x0379007 [Sec[7]] 58
step=  25 RVA=0x0379008 [Sec[7]] 4889442410
step=  26 RVA=0x037900D [Sec[7]] 58
step=  27 RVA=0x037900E [Sec[7]] 440f116c2410
step=  28 RVA=0x0379014 [Sec[7]] 4889442420
step=  29 RVA=0x0379019 [Sec[7]] 0f114c2428
step=  30 RVA=0x037901E [Sec[7]] 4c89742438
step=  31 RVA=0x0379023 [Sec[7]] 0f11442440
step=  32 RVA=0x0379028 [Sec[7]] 4c89442450
step=  33 RVA=0x037902D [Sec[7]] 440f117c2458
step=  34 RVA=0x0379033 [Sec[7]] e8d8000000
step=  35 RVA=0x0379110 [Sec[7]] 50
step=  36 RVA=0x0379111 [Sec[7]] 53
step=  37 RVA=0x0379112 [Sec[7]] 48c7c0b99bc8ff
step=  38 RVA=0x0379119 [Sec[7]] 488b5c2410
step=  39 RVA=0x037911E [Sec[7]] 488d1c03
step=  40 RVA=0x0379122 [Sec[7]] 48899c2480000000
step=  41 RVA=0x037912A [Sec[7]] 5b
step=  42 RVA=0x037912B [Sec[7]] 58
step=  43 RVA=0x037912C [Sec[7]] c3
```

### Sandbox Run: `eacfn` (`C:\Users\Administrator\Downloads\eacfn.sys`)

#### Sample Execution Trace (`GsDriverEntry` -> `Sec[7]` Transition)

```text
step=   1 RVA=0x0266478 [.text]  48895c2408
step=   2 RVA=0x026647D [.text]  57
step=   3 RVA=0x026647E [.text]  4883ec20
step=   4 RVA=0x0266482 [.text]  488bda
step=   5 RVA=0x0266485 [.text]  488bf9
step=   6 RVA=0x0266488 [.text]  e8bbffffff
step=   7 RVA=0x0266448 [.text]  488b05c95d0a00
step=   8 RVA=0x026644F [.text]  4885c0
step=   9 RVA=0x0266452 [.text]  741b
step=  10 RVA=0x0266454 [.text]  48b932a2df2d992b0000
step=  11 RVA=0x026645E [.text]  483bc1
step=  12 RVA=0x0266461 [.text]  740c
step=  13 RVA=0x0266463 [.text]  48f7d0
step=  14 RVA=0x0266466 [.text]  488905b35d0a00
step=  15 RVA=0x026646D [.text]  c3
step=  16 RVA=0x026648D [.text]  488bd3
step=  17 RVA=0x0266490 [.text]  488bcf
step=  18 RVA=0x0266493 [.text]  e830b2ddff
step=  19 RVA=0x00416C8 [.text]  e926334000
step=  20 RVA=0x04449F3 [Sec[7]] 488da42440feffff
step=  21 RVA=0x04449FB [Sec[7]] e80ae6f2ff
step=  22 RVA=0x037300A [Sec[7]] e806010000
step=  23 RVA=0x0373115 [Sec[7]] 50
step=  24 RVA=0x0373116 [Sec[7]] 53
step=  25 RVA=0x0373117 [Sec[7]] 48c7c058fbc8ff
step=  26 RVA=0x037311E [Sec[7]] 488b5c2410
step=  27 RVA=0x0373123 [Sec[7]] 488d1c03
step=  28 RVA=0x0373127 [Sec[7]] 48895c2420
step=  29 RVA=0x037312C [Sec[7]] 5b
step=  30 RVA=0x037312D [Sec[7]] 58
step=  31 RVA=0x037312E [Sec[7]] c3
step=  32 RVA=0x037300F [Sec[7]] 440f11642410
step=  33 RVA=0x0373015 [Sec[7]] 4c895c2420
step=  34 RVA=0x037301A [Sec[7]] 4c89742428
step=  35 RVA=0x037301F [Sec[7]] 0f117c2430
step=  36 RVA=0x0373024 [Sec[7]] 440f11442440
step=  37 RVA=0x037302A [Sec[7]] 4c89542450
step=  38 RVA=0x037302F [Sec[7]] 48897c2458
step=  39 RVA=0x0373034 [Sec[7]] 4c89642460
step=  40 RVA=0x0373039 [Sec[7]] 48896c2468
step=  41 RVA=0x037303E [Sec[7]] 440f11542470
step=  42 RVA=0x0373044 [Sec[7]] 0f11b42480000000
step=  43 RVA=0x037304C [Sec[7]] 4889942490000000
```

### Sandbox Run: `eos_prior` (`C:\Users\Administrator\Downloads\EasyAntiCheat_EOS.sys`)

#### Sample Execution Trace (`GsDriverEntry` -> `Sec[7]` Transition)

```text
step=   1 RVA=0x0255638 [.text]  48895c2408
step=   2 RVA=0x025563D [.text]  57
step=   3 RVA=0x025563E [.text]  4883ec20
step=   4 RVA=0x0255642 [.text]  488bda
step=   5 RVA=0x0255645 [.text]  488bf9
step=   6 RVA=0x0255648 [.text]  e8bbffffff
step=   7 RVA=0x0255608 [.text]  488b05812b0a00
step=   8 RVA=0x025560F [.text]  4885c0
step=   9 RVA=0x0255612 [.text]  741b
step=  10 RVA=0x0255614 [.text]  48b932a2df2d992b0000
step=  11 RVA=0x025561E [.text]  483bc1
step=  12 RVA=0x0255621 [.text]  740c
step=  13 RVA=0x0255623 [.text]  48f7d0
step=  14 RVA=0x0255626 [.text]  4889056b2b0a00
step=  15 RVA=0x025562D [.text]  c3
step=  16 RVA=0x025564D [.text]  488bd3
step=  17 RVA=0x0255650 [.text]  488bcf
step=  18 RVA=0x0255653 [.text]  e81491eeff
step=  19 RVA=0x013E76C [.text]  e902572c00
step=  20 RVA=0x0403E73 [Sec[7]] 488da42440feffff
step=  21 RVA=0x0403E7B [Sec[7]] e80094f5ff
step=  22 RVA=0x035D280 [Sec[7]] 4889742408
step=  23 RVA=0x035D285 [Sec[7]] 440f116c2410
step=  24 RVA=0x035D28B [Sec[7]] 4c894c2420
step=  25 RVA=0x035D290 [Sec[7]] 4c897c2428
step=  26 RVA=0x035D295 [Sec[7]] 440f114c2430
step=  27 RVA=0x035D29B [Sec[7]] 0f116c2440
step=  28 RVA=0x035D2A0 [Sec[7]] 4c89642450
step=  29 RVA=0x035D2A5 [Sec[7]] 0f115c2458
step=  30 RVA=0x035D2AA [Sec[7]] 50
step=  31 RVA=0x035D2AB [Sec[7]] 488d8424d0010000
step=  32 RVA=0x035D2B3 [Sec[7]] 4889442470
step=  33 RVA=0x035D2B8 [Sec[7]] 58
step=  34 RVA=0x035D2B9 [Sec[7]] 48895c2470
step=  35 RVA=0x035D2BE [Sec[7]] 0f11742478
step=  36 RVA=0x035D2C3 [Sec[7]] 4889942488000000
step=  37 RVA=0x035D2CB [Sec[7]] 4c89b42490000000
step=  38 RVA=0x035D2D3 [Sec[7]] 4c89842498000000
step=  39 RVA=0x035D2DB [Sec[7]] 4889ac24a0000000
step=  40 RVA=0x035D2E3 [Sec[7]] 4c899c24a8000000
step=  41 RVA=0x035D2EB [Sec[7]] 48898c24b0000000
step=  42 RVA=0x035D2F3 [Sec[7]] e890000000
step=  43 RVA=0x035D388 [Sec[7]] 50
```

### Sandbox Run: `eos_live:cpuid_leaf` (`C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys`)

#### Intercepted `CPUID` Instructions (`1`)

| Step | Insn RVA | Leaf (`EAX`) | Subleaf (`ECX`) | Out `EAX` | Out `EBX` | Out `ECX` | Out `EDX` |
|---|---|---|---|---|---|---|---|
| `1` | `0xFD37` | `0x40000000` | `0x2001000` | `0x0` | `0x0` | `0x0` | `0x0` |

#### Sample Execution Trace (`GsDriverEntry` -> `Sec[7]` Transition)

```text
step=   1 RVA=0x000FD37 [.text]  0fa2
step=   2 RVA=0x000FD39 [.text]  4c87c3
step=   3 RVA=0x000FD3C [.text]  4489442448
step=   4 RVA=0x000FD41 [.text]  8954244c
step=   5 RVA=0x000FD45 [.text]  894c2450
step=   6 RVA=0x000FD49 [.text]  48b8631a82f729c8dc52
step=   7 RVA=0x000FD53 [.text]  490fafc7
step=   8 RVA=0x000FD57 [.text]  48be12c6639df0fc4a7c
step=   9 RVA=0x000FD61 [.text]  4831c6
step=  10 RVA=0x000FD64 [.text]  488d7c247b
step=  11 RVA=0x000FD69 [.text]  4889f9
step=  12 RVA=0x000FD6C [.text]  31d2
step=  13 RVA=0x000FD6E [.text]  4989f0
step=  14 RVA=0x000FD71 [.text]  e88ac42600
step=  15 RVA=0x027C200 [.text]  488bc1
step=  16 RVA=0x027C203 [.text]  0fb6d2
step=  17 RVA=0x027C206 [.text]  49b90101010101010101
step=  18 RVA=0x027C210 [.text]  490fafd1
step=  19 RVA=0x027C214 [.text]  66480f6ec2
step=  20 RVA=0x027C219 [.text]  0f16c0
step=  21 RVA=0x027C21C [.text]  4983f840
step=  22 RVA=0x027C220 [.text]  726e
step=  23 RVA=0x027C222 [.text]  f60517b00a0002
step=  24 RVA=0x027C229 [.text]  740d
```

### Sandbox Run: `eos_live:kuser_2ec` (`C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys`)

#### Sample Execution Trace (`GsDriverEntry` -> `Sec[7]` Transition)

```text
step=   1 RVA=0x01D19B7 [.text]  48b8ec02000080f7ffff
step=   2 RVA=0x01D19C1 [.text]  8a00
step=   3 RVA=0x01D19C3 [.text]  c3
```

