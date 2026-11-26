# Automated C++20 Ground-Truth Verification Report (`eac_inspector`)

- **Overall Verification Status**: `PASS (Exit 0)`
- **Kernel RVA & Opcode Assertions Passed**: `34 / 34`
- **Rolling Cipher Algebraic Round-Trip Self-Test**: `PASS` (`11` payload sizes)
- **Signed Integrity Catalog (`base.bin`)**: `SKIPPED` (optional host file absent)
- **WDM Kernel Sandbox Emulation (`wdk_sandbox`)**: `7` runs via `unicorn.dll` (`7/7` synthetic WDK/relocation assertions `PASS`)

## 1. Measured PE32 / PE32+ Binary Inventory

| Key | Arch | Size (Bytes) | `ImageBase` | `SizeOfImage` | `EntryRVA` | `TimeDateStamp` | `.pdata` | Imports (`.bearimp`) | Exports | SHA-256 |
|---|---|---|---|---|---|---|---|---|---|---|
| `eos_live` | `x86_64` | `46171808` | `0x140000000` | `0x2C57000` | `0x27C438` | `0x6AFBE7DD` | `5602` | `1` | `0` | `3eabcfe97e8a2bde0b3db1ab1645c66c8183f053588699d3409d93d2235c5d2b` |
| `eac_dumped` | `x86_64` | `40251392` | `0xFFFFF80496FE0000` | `0x2663000` | `0x26AEB8` | `0x6AF4266C` | `5545` | `1` | `0` | `7dbd776dd7ba7a5fbd33be53829f02d0df6212ff57bcee9b2456e365d5deddd2` |
| `eacfn` | `x86_64` | `43213824` | `0xFFFFF80400000000` | `0x2937000` | `0x266478` | `0x6ABFFE92` | `5556` | `119 (119)` | `0` | `c5ee0a9cf392feef75b88025bdfc7634276165969ee8b422eef78ffef6b09fd0` |
| `eos_prior` | `x86_64` | `44398752` | `0x140000000` | `0x2AA6000` | `0x255638` | `0x6A86EBF5` | `5470` | `1` | `0` | `4e566f772c4c78066eba0187a276e10618312c63d766e0bd1c0a9d782256f734` |
| `service_v159` | `x86` | `1041336` | `0x400000` | `0x103000` | `0x83840` | `0x6AA16B40` | `0` | `245` | `0` | `0bbe6d48f45fc155f1c1d029df8de67f221b7329010164eda2dd06d7978340b9` |
| `service_v153` | `x86` | `985896` | `0x400000` | `0xF3000` | `0x74200` | `0x69B94BB9` | `0` | `245` | `0` | `b8f03456397d455a63ac36593acc5463fe99287b4088a141b3cb59be54c901f6` |

## 2. Section Table Breakdown Across Analyzed Images

### `eos_live` (`C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys`)

| Index | Name | `VirtualAddress` | `VirtualSize` | `RawPtr` | `RawSize` | `Characteristics` |
|---|---|---|---|---|---|---|
| `0` | `.text` | `0x1000` | `0x27B464` | `0x400` | `0x27B600` | `0x68000020` |
| `1` | `.rdata` | `0x27D000` | `0xA9834` | `0x27BA00` | `0xA9A00` | `0x48000040` |
| `2` | `.data` | `0x327000` | `0x50D30` | `0x325400` | `0x2200` | `0xC8000040` |
| `3` | `(unnamed)` | `0x378000` | `0x7D4C` | `0x327600` | `0x7E00` | `0x48000040` |
| `4` | `.rsrc` | `0x380000` | `0x330` | `0x32F400` | `0x400` | `0x48000040` |
| `5` | `.reloc` | `0x381000` | `0x3244` | `0x32F800` | `0x3400` | `0x42000040` |
| `6` | `(unnamed)` | `0x385000` | `0x7C00` | `0x332C00` | `0x7C00` | `0x68000020` |
| `7` | `(unnamed)` | `0x38D000` | `0x28B9000` | `0x33A800` | `0x28B8400` | `0x68000000` |
| `8` | `.pdata` | `0x2C46000` | `0x11000` | `0x2BF2C00` | `0x10800` | `0x48000000` |

### `eac_dumped` (`C:\Users\Administrator\Downloads\eac_dumped.sys`)

| Index | Name | `VirtualAddress` | `VirtualSize` | `RawPtr` | `RawSize` | `Characteristics` |
|---|---|---|---|---|---|---|
| `0` | `.text` | `0x1000` | `0x269EE4` | `0x1000` | `0x269EE4` | `0x68000020` |
| `1` | `.rdata` | `0x26B000` | `0xA7924` | `0x26B000` | `0xA7924` | `0x48000040` |
| `2` | `.data` | `0x313000` | `0x50D00` | `0x313000` | `0x50D00` | `0xC8000040` |
| `3` | `(unnamed)` | `0x364000` | `0x7BE4` | `0x364000` | `0x7BE4` | `0x48000040` |
| `4` | `.rsrc` | `0x36C000` | `0x330` | `0x36C000` | `0x330` | `0x48000040` |
| `5` | `.reloc` | `0x36D000` | `0x3228` | `0x36D000` | `0x3228` | `0x42000040` |
| `6` | `(unnamed)` | `0x371000` | `0x7A00` | `0x371000` | `0x7A00` | `0x68000020` |
| `7` | `(unnamed)` | `0x379000` | `0x22D9000` | `0x379000` | `0x22D9000` | `0x68000000` |
| `8` | `.pdata` | `0x2652000` | `0x11000` | `0x2652000` | `0x11000` | `0x48000000` |

### `eacfn` (`C:\Users\Administrator\Downloads\eacfn.sys`)

| Index | Name | `VirtualAddress` | `VirtualSize` | `RawPtr` | `RawSize` | `Characteristics` |
|---|---|---|---|---|---|---|
| `0` | `.text` | `0x1000` | `0x2654A4` | `0x1000` | `0x266000` | `0x68000020` |
| `1` | `.rdata` | `0x267000` | `0xA400C` | `0x267000` | `0xA5000` | `0x48000040` |
| `2` | `.data` | `0x30C000` | `0x50FF4` | `0x30C000` | `0x51000` | `0xC8000040` |
| `3` | `(unnamed)` | `0x35D000` | `0x7AAC` | `0x35D000` | `0x8000` | `0x48000040` |
| `4` | `.rsrc` | `0x365000` | `0x330` | `0x365000` | `0x1000` | `0x48000040` |
| `5` | `.reloc` | `0x366000` | `0x3044` | `0x366000` | `0x4000` | `0x42000040` |
| `6` | `(unnamed)` | `0x36A000` | `0x8600` | `0x36A000` | `0x9000` | `0x68000020` |
| `7` | `(unnamed)` | `0x373000` | `0x25B1000` | `0x373000` | `0x25B1000` | `0x68000000` |
| `8` | `.pdata` | `0x2924000` | `0x11000` | `0x2924000` | `0x11000` | `0x48000000` |
| `9` | `.bearimp` | `0x2935000` | `0x12DB` | `0x2935000` | `0x1400` | `0xC0000040` |

### `eos_prior` (`C:\Users\Administrator\Downloads\EasyAntiCheat_EOS.sys`)

| Index | Name | `VirtualAddress` | `VirtualSize` | `RawPtr` | `RawSize` | `Characteristics` |
|---|---|---|---|---|---|---|
| `0` | `.text` | `0x1000` | `0x254664` | `0x400` | `0x254800` | `0x68000020` |
| `1` | `.rdata` | `0x256000` | `0xA15A4` | `0x254C00` | `0xA1600` | `0x48000040` |
| `2` | `.data` | `0x2F8000` | `0x50B30` | `0x2F6200` | `0x2200` | `0xC8000040` |
| `3` | `(unnamed)` | `0x349000` | `0x76F8` | `0x2F8400` | `0x7800` | `0x48000040` |
| `4` | `.rsrc` | `0x351000` | `0x330` | `0x2FFC00` | `0x400` | `0x48000040` |
| `5` | `.reloc` | `0x352000` | `0x2FF4` | `0x300000` | `0x3000` | `0x42000040` |
| `6` | `(unnamed)` | `0x355000` | `0x7600` | `0x303000` | `0x7600` | `0x68000020` |
| `7` | `(unnamed)` | `0x35D000` | `0x2738000` | `0x30A600` | `0x2737E00` | `0x68000000` |
| `8` | `.pdata` | `0x2A95000` | `0x11000` | `0x2A42400` | `0x10200` | `0x48000000` |

### `service_v159` (`C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe`)

| Index | Name | `VirtualAddress` | `VirtualSize` | `RawPtr` | `RawSize` | `Characteristics` |
|---|---|---|---|---|---|---|
| `0` | `.text` | `0x1000` | `0xAEE5C` | `0x400` | `0xAF000` | `0x60000020` |
| `1` | `.rdata` | `0xB0000` | `0x210F4` | `0xAF400` | `0x21200` | `0x40000040` |
| `2` | `.data` | `0xD2000` | `0x38E8` | `0xD0600` | `0x1C00` | `0xC0000040` |
| `3` | `.fptable` | `0xD6000` | `0x80` | `0xD2200` | `0x200` | `0xC0000040` |
| `4` | `.tls` | `0xD7000` | `0x9` | `0xD2400` | `0x200` | `0xC0000040` |
| `5` | `.rsrc` | `0xD8000` | `0x221D8` | `0xD2600` | `0x22200` | `0x40000040` |
| `6` | `.reloc` | `0xFB000` | `0x70D4` | `0xF4800` | `0x7200` | `0x42000040` |

### `service_v153` (`C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe.bak`)

| Index | Name | `VirtualAddress` | `VirtualSize` | `RawPtr` | `RawSize` | `Characteristics` |
|---|---|---|---|---|---|---|
| `0` | `.text` | `0x1000` | `0xA29CA` | `0x400` | `0xA2A00` | `0x60000020` |
| `1` | `.rdata` | `0xA4000` | `0x1FED6` | `0xA2E00` | `0x20000` | `0x40000040` |
| `2` | `.data` | `0xC4000` | `0x37C4` | `0xC2E00` | `0x1C00` | `0xC0000040` |
| `3` | `.fptable` | `0xC8000` | `0x80` | `0xC4A00` | `0x200` | `0xC0000040` |
| `4` | `.rsrc` | `0xC9000` | `0x22200` | `0xC4C00` | `0x22200` | `0x40000040` |
| `5` | `.reloc` | `0xEC000` | `0x6D3C` | `0xE6E00` | `0x6E00` | `0x42000040` |

## 3. Reconstructed `.bearimp` Kernel Import Table (`eacfn.sys` — `119` Imports)

| # | Module | Function | IAT RVA |
|---|---|---|---|
| `1` | `FLTMGR.SYS` | `FltRegisterFilter` | `0x302890` |
| `2` | `ntoskrnl.exe` | `ExAllocatePoolWithTag` | `0x2935430` |
| `3` | `ntoskrnl.exe` | `ExFreePoolWithTag` | `0x2935438` |
| `4` | `ntoskrnl.exe` | `IoAllocateMdl` | `0x2935440` |
| `5` | `ntoskrnl.exe` | `IoFreeMdl` | `0x2935448` |
| `6` | `ntoskrnl.exe` | `IoGetCurrentProcess` | `0x2935450` |
| `7` | `ntoskrnl.exe` | `KeStackAttachProcess` | `0x2935458` |
| `8` | `ntoskrnl.exe` | `KeUnstackDetachProcess` | `0x2935460` |
| `9` | `ntoskrnl.exe` | `MmGetPhysicalAddress` | `0x2935468` |
| `10` | `ntoskrnl.exe` | `MmMapIoSpaceEx` | `0x2935470` |
| `11` | `ntoskrnl.exe` | `MmMapLockedPagesSpecifyCache` | `0x2935478` |
| `12` | `ntoskrnl.exe` | `MmProbeAndLockPages` | `0x2935480` |
| `13` | `ntoskrnl.exe` | `MmUnlockPages` | `0x2935488` |
| `14` | `ntoskrnl.exe` | `MmUnmapIoSpace` | `0x2935490` |
| `15` | `ntoskrnl.exe` | `MmUnmapLockedPages` | `0x2935498` |
| `16` | `ntoskrnl.exe` | `NtAllocateVirtualMemory` | `0x29354A0` |
| `17` | `ntoskrnl.exe` | `NtClose` | `0x29354A8` |
| `18` | `ntoskrnl.exe` | `NtFreeVirtualMemory` | `0x29354B0` |
| `19` | `ntoskrnl.exe` | `NtGetNextProcess` | `0x29354B8` |
| `20` | `ntoskrnl.exe` | `NtQuerySystemInformation` | `0x29354C0` |
| `21` | `ntoskrnl.exe` | `ObOpenObjectByPointer` | `0x29354C8` |
| `22` | `ntoskrnl.exe` | `ObReferenceObjectByHandle` | `0x29354D0` |
| `23` | `ntoskrnl.exe` | `ObfDereferenceObject` | `0x29354D8` |
| `24` | `ntoskrnl.exe` | `PsAcquireProcessExitSynchronization` | `0x29354E0` |
| `25` | `ntoskrnl.exe` | `PsGetProcessId` | `0x29354E8` |
| `26` | `ntoskrnl.exe` | `PsGetProcessWow64Process` | `0x29354F0` |
| `27` | `ntoskrnl.exe` | `PsLookupProcessByProcessId` | `0x29354F8` |
| `28` | `ntoskrnl.exe` | `PsReleaseProcessExitSynchronization` | `0x2935500` |
| `29` | `ntoskrnl.exe` | `RtlWriteRegistryValue` | `0x2935508` |
| `30` | `ntoskrnl.exe` | `ZwClose` | `0x2935510` |
| `31` | `ntoskrnl.exe` | `ZwFlushKey` | `0x2935518` |
| `32` | `ntoskrnl.exe` | `ZwOpenKey` | `0x2935520` |
| `33` | `ntoskrnl.exe` | `__C_specific_handler` | `0x2935528` |
| `34` | `ntoskrnl.exe` | `DbgSetDebugPrintCallback` | `0x2935530` |
| `35` | `ntoskrnl.exe` | `ExAcquireFastMutex` | `0x2935538` |
| `36` | `ntoskrnl.exe` | `ExReleaseFastMutex` | `0x2935540` |
| `37` | `ntoskrnl.exe` | `HalAcpiGetTableEx` | `0x2935548` |
| `38` | `ntoskrnl.exe` | `HalGetBusDataByOffset` | `0x2935550` |
| `39` | `ntoskrnl.exe` | `IoCreateDevice` | `0x2935558` |
| `40` | `ntoskrnl.exe` | `IoWMIOpenBlock` | `0x2935560` |
| `41` | `ntoskrnl.exe` | `KeInitializeEvent` | `0x2935568` |
| `42` | `ntoskrnl.exe` | `KeInitializeMutex` | `0x2935570` |
| `43` | `ntoskrnl.exe` | `KeInitializeSemaphore` | `0x2935578` |
| `44` | `ntoskrnl.exe` | `KeReleaseMutex` | `0x2935580` |
| `45` | `ntoskrnl.exe` | `KeWaitForMutexObject` | `0x2935588` |
| `46` | `ntoskrnl.exe` | `MmAllocateContiguousNodeMemory` | `0x2935590` |
| `47` | `ntoskrnl.exe` | `MmGetVirtualForPhysical` | `0x2935598` |
| `48` | `ntoskrnl.exe` | `MmIsAddressValid` | `0x29355A0` |
| `49` | `ntoskrnl.exe` | `NtCreateSection` | `0x29355A8` |
| `50` | `ntoskrnl.exe` | `NtMapViewOfSection` | `0x29355B0` |
| `51` | `ntoskrnl.exe` | `NtOpenDirectoryObject` | `0x29355B8` |
| `52` | `ntoskrnl.exe` | `NtOpenFile` | `0x29355C0` |
| `53` | `ntoskrnl.exe` | `NtOpenKey` | `0x29355C8` |
| `54` | `ntoskrnl.exe` | `NtQuerySystemInformationEx` | `0x29355D0` |
| `55` | `ntoskrnl.exe` | `NtQueryValueKey` | `0x29355D8` |
| `56` | `ntoskrnl.exe` | `NtUnmapViewOfSection` | `0x29355E0` |
| `57` | `ntoskrnl.exe` | `ObGetObjectType` | `0x29355E8` |
| `58` | `ntoskrnl.exe` | `PsCreateSystemThread` | `0x29355F0` |
| `59` | `ntoskrnl.exe` | `PsGetProcessImageFileName` | `0x29355F8` |
| `60` | `ntoskrnl.exe` | `RtlCompareString` | `0x2935600` |
| `61` | `ntoskrnl.exe` | `RtlDeleteRegistryValue` | `0x2935608` |
| `62` | `ntoskrnl.exe` | `RtlMultiByteToUnicodeN` | `0x2935610` |
| `63` | `ntoskrnl.exe` | `ExAcquireFastMutexUnsafe` | `0x2935618` |
| `64` | `ntoskrnl.exe` | `ExAcquirePushLockExclusiveEx` | `0x2935620` |
| `65` | `ntoskrnl.exe` | `ExAcquireResourceExclusiveLite` | `0x2935628` |
| `66` | `ntoskrnl.exe` | `ExReleaseFastMutexUnsafe` | `0x2935630` |
| `67` | `ntoskrnl.exe` | `ExReleasePushLockExclusiveEx` | `0x2935638` |
| `68` | `ntoskrnl.exe` | `ExReleaseResourceLite` | `0x2935640` |
| `69` | `ntoskrnl.exe` | `IoDeleteDevice` | `0x2935648` |
| `70` | `ntoskrnl.exe` | `IoDeleteSymbolicLink` | `0x2935650` |
| `71` | `ntoskrnl.exe` | `IoGetDeviceInterfaces` | `0x2935658` |
| `72` | `ntoskrnl.exe` | `IoRegisterPlugPlayNotification` | `0x2935660` |
| `73` | `ntoskrnl.exe` | `IoUnregisterPlugPlayNotificationEx` | `0x2935668` |
| `74` | `ntoskrnl.exe` | `KeAreAllApcsDisabled` | `0x2935670` |
| `75` | `ntoskrnl.exe` | `KeClearEvent` | `0x2935678` |
| `76` | `ntoskrnl.exe` | `KeDelayExecutionThread` | `0x2935680` |
| `77` | `ntoskrnl.exe` | `KeEnterCriticalRegion` | `0x2935688` |
| `78` | `ntoskrnl.exe` | `KeLeaveCriticalRegion` | `0x2935690` |
| `79` | `ntoskrnl.exe` | `KeQueryPerformanceCounter` | `0x2935698` |
| `80` | `ntoskrnl.exe` | `KeQueryTimeIncrement` | `0x29356A0` |
| `81` | `ntoskrnl.exe` | `KeReleaseSemaphore` | `0x29356A8` |
| `82` | `ntoskrnl.exe` | `KeSetBasePriorityThread` | `0x29356B0` |
| `83` | `ntoskrnl.exe` | `KeSetEvent` | `0x29356B8` |
| `84` | `ntoskrnl.exe` | `MmCopyMemory` | `0x29356C0` |
| `85` | `ntoskrnl.exe` | `MmFreeContiguousMemory` | `0x29356C8` |
| `86` | `ntoskrnl.exe` | `NtCreateFile` | `0x29356D0` |
| `87` | `ntoskrnl.exe` | `NtCreateKey` | `0x29356D8` |
| `88` | `ntoskrnl.exe` | `NtDeleteValueKey` | `0x29356E0` |
| `89` | `ntoskrnl.exe` | `NtEnumerateValueKey` | `0x29356E8` |
| `90` | `ntoskrnl.exe` | `NtManageHotPatch` | `0x29356F0` |
| `91` | `ntoskrnl.exe` | `NtOpenSection` | `0x29356F8` |
| `92` | `ntoskrnl.exe` | `NtQueryDirectoryObject` | `0x2935700` |
| `93` | `ntoskrnl.exe` | `NtQueryFullAttributesFile` | `0x2935708` |
| `94` | `ntoskrnl.exe` | `NtQueryInformationProcess` | `0x2935710` |
| `95` | `ntoskrnl.exe` | `NtQueryLicenseValue` | `0x2935718` |
| `96` | `ntoskrnl.exe` | `NtQuerySystemEnvironmentValueEx` | `0x2935720` |
| `97` | `ntoskrnl.exe` | `NtSetValueKey` | `0x2935728` |
| `98` | `ntoskrnl.exe` | `ObOpenObjectByName` | `0x2935730` |
| `99` | `ntoskrnl.exe` | `ObfReferenceObject` | `0x2935738` |
| `100` | `ntoskrnl.exe` | `PsDereferencePrimaryToken` | `0x2935740` |
| `101` | `ntoskrnl.exe` | `PsGetProcessExitProcessCalled` | `0x2935748` |
| `102` | `ntoskrnl.exe` | `PsGetProcessPeb` | `0x2935750` |
| `103` | `ntoskrnl.exe` | `PsGetProcessSectionBaseAddress` | `0x2935758` |
| `104` | `ntoskrnl.exe` | `PsIsProtectedProcess` | `0x2935760` |
| `105` | `ntoskrnl.exe` | `PsLookupThreadByThreadId` | `0x2935768` |
| `106` | `ntoskrnl.exe` | `PsReferencePrimaryToken` | `0x2935770` |
| `107` | `ntoskrnl.exe` | `PsReferenceProcessFilePointer` | `0x2935778` |
| `108` | `ntoskrnl.exe` | `PsTerminateSystemThread` | `0x2935780` |
| `109` | `ntoskrnl.exe` | `RtlCompareUnicodeString` | `0x2935788` |
| `110` | `ntoskrnl.exe` | `RtlGetDefaultCodePage` | `0x2935790` |
| `111` | `ntoskrnl.exe` | `RtlUnicodeToUTF8N` | `0x2935798` |
| `112` | `ntoskrnl.exe` | `SeQueryInformationToken` | `0x29357A0` |
| `113` | `ntoskrnl.exe` | `_vsnwprintf` | `0x29357A8` |
| `114` | `ntoskrnl.exe` | `KeQuerySystemTimePrecise` | `0x29357B0` |
| `115` | `ntoskrnl.exe` | `IofCompleteRequest` | `0x29357B8` |
| `116` | `msrpc.sys` | `RpcAsyncInitializeHandle` | `0x2936260` |
| `117` | `msrpc.sys` | `RpcBindingBind` | `0x2936268` |
| `118` | `msrpc.sys` | `RpcBindingCreateW` | `0x2936270` |
| `119` | `msrpc.sys` | `RpcBindingFree` | `0x2936278` |

## Kernel Driver Cross-Build Signature & RVA Scan

| Driver | `.text` `cpuid` | `Sec[7]` `cpuid` | `KUSER_SHARED_DATA` `movabs` | `.rdata` `'RSMB'` | `0x2D1400` Stores | `SMART` Sites | Checks Passed |
|---|---|---|---|---|---|---|---|
| `eos_live` | `30` | `99` | `25` | `0x303B74` | `1` | `0` | `8/8` |
| `eac_dumped` | `27` | `83` | `27` | `0x2D458C` | `1` | `0` | `8/8` |
| `eacfn` | `30` | `61` | `26` | `0x2C5C8C` | `1` | `1` | `10/10` |
| `eos_prior` | `29` | `84` | `23` | `0x2BE27C` | `0` | `1` | `8/8` |

### Verified `KUSER_SHARED_DATA` (`0xFFFFF78000000000`) Reads

| Offset | DDK Struct Field | `eos_live` RVAs | `eac_dumped` RVAs | `eacfn` RVAs | `eos_prior` RVAs | 
|---|---|---|---|---|---|
| `+0x008` | `InterruptTime` | `0xCCCBE`, `0x1017A3`, `0x1426D7E` (Sec[7] (VM/Flat)), `0x184EC74` (Sec[7] (VM/Flat)), `0x1B4B3AE` (Sec[7] (VM/Flat)) | `0x4CF6B`, `0x15187B`, `0x17AA7C`, `0xE5AF85` (Sec[7] (VM/Flat)), `0x19B87DB` (Sec[7] (VM/Flat)) | `0x4E032`, `0x13C959`, `0x146022`, `0x1F71D8D` (Sec[7] (VM/Flat)), `0x2141F52` (Sec[7] (VM/Flat)) | `0xCABBB`, `0x147E42`, `0x1F100C`, `0x16C53C4` (Sec[7] (VM/Flat)) | 
| `+0x014` | `SystemTime` | `0xCCA5B`, `0xF794B`, `0x157415`, `0x171B6A`, `0x133126F` (Sec[7] (VM/Flat)), `0x15A9D1A` (Sec[7] (VM/Flat)), `0x1EE86F8` (Sec[7] (VM/Flat)), `0x1F85742` (Sec[7] (VM/Flat)) | `0x171FE2`, `0x17A827`, `0x1B286A`, `0x1CD486`, `0x1F2A10`, `0x12DB663` (Sec[7] (VM/Flat)), `0x151B4C7` (Sec[7] (VM/Flat)), `0x186E71D` (Sec[7] (VM/Flat)), `0x21D5096` (Sec[7] (VM/Flat)) | `0x4DDE3`, `0x9A2E1`, `0xA590D`, `0x1C6C32`, `0x126C56E` (Sec[7] (VM/Flat)), `0x1317748` (Sec[7] (VM/Flat)), `0x1AA87DE` (Sec[7] (VM/Flat)), `0x216822E` (Sec[7] (VM/Flat)) | `0x105CF9`, `0x1DC687`, `0x1EB817`, `0x1F937A`, `0x17E776A` (Sec[7] (VM/Flat)), `0x17F8753` (Sec[7] (VM/Flat)), `0x1D83B27` (Sec[7] (VM/Flat)), `0x2914C1A` (Sec[7] (VM/Flat)) | 
| `+0x020` | `TimeZoneBias` | `0x1E12EB`, `0x1ADA0B1` (Sec[7] (VM/Flat)) | `0x1C95B8A` (Sec[7] (VM/Flat)), `0x25ADDE3` (Sec[7] (VM/Flat)) | `0x15E8E6C` (Sec[7] (VM/Flat)), `0x1FBF7CB` (Sec[7] (VM/Flat)) | `0x13143F`, `0x1A0073` | 
| `+0x260` | `NtBuildNumber` | `0x542CC`, `0x1D1A48`, `0x18D420D` (Sec[7] (VM/Flat)), `0x234DDD5` (Sec[7] (VM/Flat)) | `0xF59A`, `0x149AAF`, `0x21EFF0`, `0x18717D8` (Sec[7] (VM/Flat)), `0x1871824` (Sec[7] (VM/Flat)) | `0x8D2FC`, `0x1CB13B`, `0x1B02C4E` (Sec[7] (VM/Flat)), `0x2364242` (Sec[7] (VM/Flat)), `0x23642BB` (Sec[7] (VM/Flat)) | `0x1360D0`, `0x207E6D`, `0x187B391` (Sec[7] (VM/Flat)) | 
| `+0x274` | `ProcessorFeatures[0]` | `0xEFC8B` | `0x2091C8` | `0x2100DE` | `0x1B11B9` | 
| `+0x2EC` | `SafeBootMode` | `0x1D19B7` | `0x21EF4E` | `0x1CB08C` | `0x207DCA` | 
| `+0x320` | `TickCount` | `0xAD4E1`, `0xCC95C`, `0x145EC8`, `0x1C0AD5` | `0x342ED`, `0x17A739`, `0x19FEC4`, `0xF1EA30` (Sec[7] (VM/Flat)) | `0x370A3`, `0x4DCF5`, `0x1EFC7E`, `0x1BD9DC8` (Sec[7] (VM/Flat)) | `0xDB729`, `0x151B35`, `0x187003`, `0x1F9289` | 

### Ground-Truth Byte Verification Checks

| Driver | Check | RVA | Result | Observed Bytes | Notes |
|---|---|---|---|---|---|
| `eos_live` | DriverEntry RVA mapped | `0x27C438` | PASS | `48 89 5c 24 08 57 48 83 ec 20 48 8b da` | PE OptionalHeader.AddressOfEntryPoint maps to executable bytes |
| `eos_live` | RSMB .rdata template | `0x303B74` | PASS | `42 4d 53 52 01 00 00 00 00 00 00 00 00` | SYSTEM_FIRMWARE_TABLE_INFORMATION ('RSMB', Action=1) |
| `eos_live` | MBR:%08x UTF-16LE formatter | `0x31D146` | PASS | `4d 00 42 00 52 00 3a 00 25 00 30 00 38` | Disk layout telemetry wide format string in .rdata |
| `eos_live` | KUSER_SHARED_DATA+0x2EC (SafeBootMode) | `0x1D19B7` | PASS | `48 b8 ec 02 00 00 80 f7 ff ff 8a 00 c3` | 10-byte movabs 0xFFFFF780000002EC + 1-byte SafeBootMode read |
| `eos_live` | KUSER_SHARED_DATA+0x014 (SystemTime) | `0xCCA5B` | PASS | `48 b8 14 00 00 00 80 f7 ff ff` | Exact opcode boundary for KSYSTEM_TIME SystemTime read |
| `eos_live` | KUSER_SHARED_DATA+0x274 (ProcessorFeatures) | `0xEFC8B` | PASS | `48 b9 74 02 00 00 80 f7 ff ff` | Exact opcode boundary for BOOLEAN ProcessorFeatures[64] array base |
| `eos_live` | IOCTL_STORAGE_QUERY_PROPERTY (0x2D1400) | `0x2A57F24` | PASS | `c7 46 30 00 14 2d 00 c7 46 28` | IRP IO_STACK_LOCATION IoControlCode = 0x002D1400 store |
| `eos_live` | Affine pointer call-thunks in .text | `0xB6DB` | PASS | `48 b8 48 0e 7c 17 a2 27 5c 2c 49 0f af` | Total .text affine call-thunks matched: 1819 |
| `eac_dumped` | DriverEntry RVA mapped | `0x26AEB8` | PASS | `48 89 5c 24 08 57 48 83 ec 20 48 8b da` | PE OptionalHeader.AddressOfEntryPoint maps to executable bytes |
| `eac_dumped` | RSMB .rdata template | `0x2D458C` | PASS | `42 4d 53 52 01 00 00 00 00 00 00 00 00` | SYSTEM_FIRMWARE_TABLE_INFORMATION ('RSMB', Action=1) |
| `eac_dumped` | MBR:%08x UTF-16LE formatter | `0x3092B6` | PASS | `4d 00 42 00 52 00 3a 00 25 00 30 00 38` | Disk layout telemetry wide format string in .rdata |
| `eac_dumped` | KUSER_SHARED_DATA+0x2EC (SafeBootMode) | `0x21EF4E` | PASS | `48 b8 ec 02 00 00 80 f7 ff ff 8a 00 c3` | 10-byte movabs 0xFFFFF780000002EC + 1-byte SafeBootMode read |
| `eac_dumped` | KUSER_SHARED_DATA+0x014 (SystemTime) | `0x171FE2` | PASS | `48 bf 14 00 00 00 80 f7 ff ff` | Exact opcode boundary for KSYSTEM_TIME SystemTime read |
| `eac_dumped` | KUSER_SHARED_DATA+0x274 (ProcessorFeatures) | `0x2091C8` | PASS | `49 b8 74 02 00 00 80 f7 ff ff` | Exact opcode boundary for BOOLEAN ProcessorFeatures[64] array base |
| `eac_dumped` | IOCTL_STORAGE_QUERY_PROPERTY (0x2D1400) | `0x153995` | PASS | `41 c7 40 30 00 14 2d 00 41 c7` | IRP IO_STACK_LOCATION IoControlCode = 0x002D1400 store |
| `eac_dumped` | Affine pointer call-thunks in .text | `0xC069` | PASS | `48 b8 b3 2b 76 88 42 b8 61 83 49 0f af` | Total .text affine call-thunks matched: 1806 |
| `eacfn` | DriverEntry RVA mapped | `0x266478` | PASS | `48 89 5c 24 08 57 48 83 ec 20 48 8b da` | PE OptionalHeader.AddressOfEntryPoint maps to executable bytes |
| `eacfn` | RSMB .rdata template | `0x2C5C8C` | PASS | `42 4d 53 52 01 00 00 00 00 00 00 00 00` | SYSTEM_FIRMWARE_TABLE_INFORMATION ('RSMB', Action=1) |
| `eacfn` | MBR:%08x UTF-16LE formatter | `0x301B5E` | PASS | `4d 00 42 00 52 00 3a 00 25 00 30 00 38` | Disk layout telemetry wide format string in .rdata |
| `eacfn` | KUSER_SHARED_DATA+0x2EC (SafeBootMode) | `0x1CB08C` | PASS | `48 b8 ec 02 00 00 80 f7 ff ff 8a 00 c3` | 10-byte movabs 0xFFFFF780000002EC + 1-byte SafeBootMode read |
| `eacfn` | KUSER_SHARED_DATA+0x014 (SystemTime) | `0x4DDE3` | PASS | `48 b8 14 00 00 00 80 f7 ff ff` | Exact opcode boundary for KSYSTEM_TIME SystemTime read |
| `eacfn` | KUSER_SHARED_DATA+0x274 (ProcessorFeatures) | `0x2100DE` | PASS | `49 b8 74 02 00 00 80 f7 ff ff` | Exact opcode boundary for BOOLEAN ProcessorFeatures[64] array base |
| `eacfn` | IOCTL_STORAGE_QUERY_PROPERTY (0x2D1400) | `0xB90FC` | PASS | `41 c7 40 30 00 14 2d 00 41 c7` | IRP IO_STACK_LOCATION IoControlCode = 0x002D1400 store |
| `eacfn` | SMART IOCTL MBA dispatcher | `0x1CD7A24` | PASS | `48 8d 88 84 c0 07 00 48 0f af ce 48 29` | SMART_RCV_DRIVE_DATA (+0x7C0 MBA) / SMART_SEND_DRIVE_COMMAND (0x7C084) |
| `eacfn` | Affine pointer call-thunks in .text | `0xADA1` | PASS | `48 b8 06 33 5d 7f 9c 54 e8 6d 49 0f af` | Total .text affine call-thunks matched: 1790 |
| `eacfn` | .bearimp reconstructed kernel imports | `0x2935000` | PASS | `60 50 93 02 00 00 00 00 00 00 00 00` | Parsed 119 imports across FLTMGR.SYS, ntoskrnl.exe, msrpc.sys |
| `eos_prior` | DriverEntry RVA mapped | `0x255638` | PASS | `48 89 5c 24 08 57 48 83 ec 20 48 8b da` | PE OptionalHeader.AddressOfEntryPoint maps to executable bytes |
| `eos_prior` | RSMB .rdata template | `0x2BE27C` | PASS | `42 4d 53 52 01 00 00 00 00 00 00 00 00` | SYSTEM_FIRMWARE_TABLE_INFORMATION ('RSMB', Action=1) |
| `eos_prior` | MBR:%08x UTF-16LE formatter | `0x2EF232` | PASS | `4d 00 42 00 52 00 3a 00 25 00 30 00 38` | Disk layout telemetry wide format string in .rdata |
| `eos_prior` | KUSER_SHARED_DATA+0x2EC (SafeBootMode) | `0x207DCA` | PASS | `48 b8 ec 02 00 00 80 f7 ff ff 8a 00 c3` | 10-byte movabs 0xFFFFF780000002EC + 1-byte SafeBootMode read |
| `eos_prior` | KUSER_SHARED_DATA+0x014 (SystemTime) | `0x105CF9` | PASS | `48 b8 14 00 00 00 80 f7 ff ff` | Exact opcode boundary for KSYSTEM_TIME SystemTime read |
| `eos_prior` | KUSER_SHARED_DATA+0x274 (ProcessorFeatures) | `0x1B11B9` | PASS | `49 b9 74 02 00 00 80 f7 ff ff` | Exact opcode boundary for BOOLEAN ProcessorFeatures[64] array base |
| `eos_prior` | SMART IOCTL MBA dispatcher | `0x8A3B36` | PASS | `45 8d 88 c0 07 00 00 41 81 e1 ff ff ff` | SMART_RCV_DRIVE_DATA (+0x7C0 MBA) / SMART_SEND_DRIVE_COMMAND (0x7C084) |
| `eos_prior` | Affine pointer call-thunks in .text | `0xC458` | PASS | `48 b8 7b 67 40 3d eb 57 46 5a 49 0f af` | Total .text affine call-thunks matched: 1769 |

### Sample Per-Call Affine Pointer Decryption Thunks (`.text`)

| Driver | Thunk RVA | `C_MUL` (`movabs rax`) | Encrypted Slot RVA | Raw Slot Value (`uint64_t`) |
|---|---|---|---|---|
| `eos_live` | `0xB6DB` | `0x2C5C27A2177C0E48` | `0x313808` | `0xC255D0635949F668` |
| `eos_live` | `0xBB0A` | `0x237316BDCF16F466` | `0x313810` | `0x1EE010400D7A141A` |
| `eos_live` | `0xCEC4` | `0x39C652D369428F3A` | `0x318B30` | `0x708358B3C37B6351` |
| `eos_live` | `0xCEE7` | `0x39C652D369428F3A` | `0x318B30` | `0x708358B3C37B6351` |
| `eos_live` | `0xCF57` | `0x41B87B7CA77F0AFD` | `0x318B38` | `0x6AFDC1840D8E8EC5` |
| `eos_live` | `0xDEA7` | `0x7285763C3CE1739D` | `0x318B58` | `0x87D6C2C4782E4865` |
| `eac_dumped` | `0xC069` | `0x8361B84288762BB3` | `0x2FFA10` | `0x4C5582F85DBD08E3` |
| `eac_dumped` | `0xC172` | `0x39BC5BBD8118F8CC` | `0x2FFA08` | `0xA704907E7E2DE851` |
| `eac_dumped` | `0xC1CF` | `0x8361B84288762BB3` | `0x2FFA10` | `0x4C5582F85DBD08E3` |
| `eac_dumped` | `0xC249` | `0x8361B84288762BB3` | `0x2FFA10` | `0x4C5582F85DBD08E3` |
| `eac_dumped` | `0xE889` | `0x2DC2A398E0D6C69F` | `0x2FFA20` | `0xF527AA998FE04EAC` |
| `eac_dumped` | `0xE9DF` | `0x44F89CAB5F0DB867` | `0x2FFA30` | `0xDC88D51F21F53347` |
| `eacfn` | `0xADA1` | `0x6DE8549C7F5D3306` | `0x2F8370` | `0x9B5A5A4231E5E800` |
| `eacfn` | `0xC778` | `0xACBBCD1752EA1E56` | `0x2F8380` | `0x6ABB109D692EA92E` |
| `eacfn` | `0xC86D` | `0x07DFFB9F79D90A4B` | `0x2F8388` | `0xBA79FE846C1381B6` |
| `eacfn` | `0xC91D` | `0xC205D029254ADA29` | `0x2F8390` | `0x9B6E46F456ECDDE4` |
| `eacfn` | `0xC970` | `0xAEC9276362D12042` | `0x2F8398` | `0x9639BAA9A01EB528` |
| `eacfn` | `0xCAAB` | `0xBEF4398C72DA2B1A` | `0x2F83A0` | `0xE1A6051C7E6F8116` |
| `eos_prior` | `0xC458` | `0x5A4657EB3D40677B` | `0x2EB4F8` | `0xD5126B51959C15C3` |
| `eos_prior` | `0xC5AD` | `0x97122B8D898002BE` | `0x2E6378` | `0x140BE687E4B6551B` |
| `eos_prior` | `0xC774` | `0xC7A1B73CF0F47408` | `0x2E6380` | `0x02A4CA5B51E308D8` |
| `eos_prior` | `0xC7FF` | `0xD2CCD5D4564FC2F9` | `0x2E6388` | `0x1B268C66722605A5` |
| `eos_prior` | `0xC83B` | `0x5B3E44667D98D580` | `0x2E6390` | `0x83724DBC90497021` |
| `eos_prior` | `0xE21E` | `0xBC038B1ED6532EF1` | `0x2E6440` | `0xD8DDA5600C623DB1` |

## Protocol, Cipher, Catalog & EOSSDK Verification

### 1. `Global\EasyAntiCheat_EOSBin` Rolling Byte-Cipher (`0x0042499a..0x00424a0d`)
- **Self-Test Status**: `PASS`
- **Sizes Verified**: `11` (`Bit-exact round-trip verified across 11 buffer sizes (0..4096, odd & even)`)

### 2. Signed Integrity Catalog (`Certificates/base.bin`)
- **Status**: `SKIPPED` (optional host file absent on this machine)

### 3. Service Binary Evolution (`EasyAntiCheat_EOS.exe` v1.5.9 vs v1.5.3 `.bak`)

| Metric | `v1.5.9` (Live) | `v1.5.3` (`.bak`) |
|---|---|---|
| File Size (Bytes) | `1041336` | `985896` |
| SHA-256 | `0bbe6d48f45fc155f1c1d029df8de67f221b7329010164eda2dd06d7978340b9` | `b8f03456397d455a63ac36593acc5463fe99287b4088a141b3cb59be54c901f6` |
| `EntryRVA` / `SizeOfImage` | `0x83840` / `0x103000` | `0x74200` / `0xf3000` |
| Section Count | `7` (`.tls` present) | `6` |
| `tbs.dll` / `ncrypt.dll` Imports | `5` / `4` | `5` / `4` |
| `ws2_32.dll` / `crypt32.dll` Imports | `25` / `15` | `25` / `15` |

### 4. `EOSSDK-Win64-Shipping.dll` Anti-Cheat Exports (`0` Client, `0` Server)

- **Status**: `SKIPPED` (optional host `EOSSDK-Win64-Shipping.dll` absent on this machine)

## WDM Kernel Driver Sandbox Emulation (`wdk_sandbox` — C++20 + Unicorn x86_64)

Full PE64 image mapping at `0x0000000140000000` with `IMAGE_REL_BASED_DIR64` base relocation rebasing, `LOAD_CONFIG` `__security_cookie` pre-initialization, synthesized `_DRIVER_OBJECT` (`RCX`), `_UNICODE_STRING RegistryPath` (`RDX`), `GS_BASE` (`_KPCR` / `_KPRCB` / `_KTHREAD` / `_EPROCESS`), `KUSER_SHARED_DATA` (`0xFFFFF78000000000`), `CPUID` bare-metal interception, and `.bearimp` / IAT kernel API trampolines.

| Target | `StartRVA` | `LastRVA` | Insns Executed | `.text` Insns | `Sec[7]` Insns | Basic Blocks | Relocs Applied | Auto-Mapped Pages | `KUSER` Reads | `CPUID` Traps | Stub Calls | Stop Reason |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `eos_live` | `0x27C438` | `0x1B363BB` | `100000` | `754` | `99246` | `1010` | `0` | `0` | `2` | `0` | `0` | `instruction_budget_reached` |
| `eac_dumped` | `0x26AEB8` | `0x85EE5B` | `100000` | `297` | `99703` | `1006` | `6276` | `1` | `2` | `0` | `0` | `instruction_budget_reached` |
| `eacfn` | `0x266478` | `0x188AEEE` | `100000` | `397` | `99603` | `1021` | `6036` | `1` | `2` | `0` | `0` | `instruction_budget_reached` |
| `eos_prior` | `0x255638` | `0x118B51E` | `100000` | `307` | `99693` | `998` | `0` | `0` | `2` | `0` | `0` | `instruction_budget_reached` |
| `eos_live:cpuid_leaf` | `0xFD37` | `0x27C3C4` | `32` | `32` | `0` | `7` | `0` | `0` | `0` | `1` | `0` | `instruction_budget_reached` |
| `eos_live:kuser_2ec` | `0x1D19B7` | `0x1D19C3` | `3` | `3` | `0` | `1` | `0` | `0` | `1` | `0` | `0` | `clean_return_ntstatus_0x200` |
| `eos_live:flt_register` | `0x27C400` | `0x27C400` | `1` | `1` | `0` | `2` | `0` | `0` | `0` | `0` | `1` | `clean_return_ntstatus_0x0` |

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

### Sandbox Run: `eos_live:flt_register` (`C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys`)

#### Intercepted Kernel Import Trampoline Calls (`1`)

| Step | Caller RVA | Module | Function | `RCX` | `RDX` | `R8` | Return (`RAX`) |
|---|---|---|---|---|---|---|---|
| `1` | `0x0` | `FLTMGR.SYS` | `FltRegisterFilter` | `0x7FF802001000` | `0x7FF802002000` | `0x0` | `0x0` |

#### Sample Execution Trace (`GsDriverEntry` -> `Sec[7]` Transition)

```text
step=   1 RVA=0x027C400 [.text]  ff25721a0a00
```

