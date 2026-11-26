# Automated C++20 Ground-Truth Verification Report (`eac_inspector`)

- **Overall Verification Status**: `PASS (Exit 0)`
- **Kernel RVA & Opcode Assertions Passed**: `34 / 34`
- **Rolling Cipher Algebraic Round-Trip Self-Test**: `PASS` (`11` payload sizes)
- **Signed Integrity Catalog (`base.bin`)**: `VALID` (`v5`, `62621` B, SHA-256 `04e4d80cbdeef7d28cca8853ec60b491ec2eab46374d05c82229f0f42db60e5c`)

## 1. Measured PE32 / PE32+ Binary Inventory

| Key | Arch | Size (Bytes) | `ImageBase` | `SizeOfImage` | `EntryRVA` | `TimeDateStamp` | `.pdata` | Imports (`.bearimp`) | Exports | SHA-256 |
|---|---|---|---|---|---|---|---|---|---|---|
| `eos_live` | `x86_64` | `46171808` | `0x140000000` | `0x2C57000` | `0x27C438` | `0x6AFBE7DD` | `5602` | `1` | `0` | `3eabcfe97e8a2bde0b3db1ab1645c66c8183f053588699d3409d93d2235c5d2b` |
| `eac_dumped` | `x86_64` | `40251392` | `0xFFFFF80496FE0000` | `0x2663000` | `0x26AEB8` | `0x6AF4266C` | `5545` | `1` | `0` | `7dbd776dd7ba7a5fbd33be53829f02d0df6212ff57bcee9b2456e365d5deddd2` |
| `eacfn` | `x86_64` | `43213824` | `0xFFFFF80400000000` | `0x2937000` | `0x266478` | `0x6ABFFE92` | `5556` | `119 (119)` | `0` | `c5ee0a9cf392feef75b88025bdfc7634276165969ee8b422eef78ffef6b09fd0` |
| `eos_prior` | `x86_64` | `44398752` | `0x140000000` | `0x2AA6000` | `0x255638` | `0x6A86EBF5` | `5470` | `1` | `0` | `4e566f772c4c78066eba0187a276e10618312c63d766e0bd1c0a9d782256f734` |
| `service_v159` | `x86` | `1041336` | `0x400000` | `0x103000` | `0x83840` | `0x6AA16B40` | `0` | `245` | `0` | `0bbe6d48f45fc155f1c1d029df8de67f221b7329010164eda2dd06d7978340b9` |
| `service_v153` | `x86` | `985896` | `0x400000` | `0xF3000` | `0x74200` | `0x69B94BB9` | `0` | `245` | `0` | `b8f03456397d455a63ac36593acc5463fe99287b4088a141b3cb59be54c901f6` |
| `launcher_eos` | `x86_64` | `5210040` | `0x140000000` | `0x502000` | `0x2A37C0` | `0x6AE1DD7A` | `12995` | `419` | `0` | `ece78de48adf5793902f312ea520822530120c2ab240e016531daab21024283b` |
| `eossdk` | `x86_64` | `47839632` | `0x180000000` | `0x2E92000` | `0x1A6D9F0` | `0x6ADBA68D` | `80681` | `536` | `1086` | `7c3310271c39c19b140554f7263813853ce3c116636f7cb1c85ba35c056811e2` |

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

### `launcher_eos` (`C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping_EAC_EOS.exe`)

| Index | Name | `VirtualAddress` | `VirtualSize` | `RawPtr` | `RawSize` | `Characteristics` |
|---|---|---|---|---|---|---|
| `0` | `.text` | `0x1000` | `0x2E3D96` | `0x600` | `0x2E3E00` | `0x60000020` |
| `1` | `.rdata` | `0x2E5000` | `0x1B7EF4` | `0x2E4400` | `0x1B8000` | `0x40000040` |
| `2` | `.data` | `0x49D000` | `0x11BD8` | `0x49C400` | `0x9C00` | `0xC0000040` |
| `3` | `.pdata` | `0x4AF000` | `0x26124` | `0x4A6000` | `0x26200` | `0x40000040` |
| `4` | `.fptable` | `0x4D6000` | `0x100` | `0x4CC200` | `0x200` | `0xC0000040` |
| `5` | `.tls` | `0x4D7000` | `0x9` | `0x4CC400` | `0x200` | `0xC0000040` |
| `6` | `_RDATA` | `0x4D8000` | `0x1F4` | `0x4CC600` | `0x200` | `0x40000040` |
| `7` | `.rsrc` | `0x4D9000` | `0x21D58` | `0x4CC800` | `0x21E00` | `0x40000040` |
| `8` | `.reloc` | `0x4FB000` | `0x6E64` | `0x4EE600` | `0x7000` | `0x42000040` |

### `eossdk` (`C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EOSSDK-Win64-Shipping.dll`)

| Index | Name | `VirtualAddress` | `VirtualSize` | `RawPtr` | `RawSize` | `Characteristics` |
|---|---|---|---|---|---|---|
| `0` | `.text` | `0x1000` | `0x1A74901` | `0x400` | `0x1A74A00` | `0x60000020` |
| `1` | `malloc_h` | `0x1A76000` | `0x7D9` | `0x1A74E00` | `0x800` | `0x60000020` |
| `2` | `.rodata` | `0x1A77000` | `0x8C0` | `0x1A75600` | `0xA00` | `0x60000020` |
| `3` | `.rdata` | `0x1A78000` | `0x11E9932` | `0x1A76000` | `0x11E9A00` | `0x40000040` |
| `4` | `.data` | `0x2C62000` | `0x11B788` | `0x2C5FA00` | `0x29600` | `0xC0000040` |
| `5` | `.pdata` | `0x2D7E000` | `0xEC5EC` | `0x2C89000` | `0xEC600` | `0x40000040` |
| `6` | `.eos` | `0x2E6B000` | `0xA4` | `0x2D75600` | `0x200` | `0x40000040` |
| `7` | `_RDATA` | `0x2E6C000` | `0x2308` | `0x2D75800` | `0x2400` | `0x40000040` |
| `8` | `.rsrc` | `0x2E6F000` | `0x68A8` | `0x2D77C00` | `0x6A00` | `0x40000040` |
| `9` | `.reloc` | `0x2E76000` | `0x1BEC4` | `0x2D7E600` | `0x1C000` | `0x42000040` |

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
- **Header Magic Valid (`"EAC\0"`)**: `true`
- **Catalog Version**: `5`
- **Size**: `62621` bytes
- **SHA-256**: `04e4d80cbdeef7d28cca8853ec60b491ec2eab46374d05c82229f0f42db60e5c`
- **Header (32 bytes)**: `4541430005000000619d29e8c2dd321b5eb4e8dd64e28ad737b34a7d9ec5b2e0`

### 3. Service Binary Evolution (`EasyAntiCheat_EOS.exe` v1.5.9 vs v1.5.3 `.bak`)

| Metric | `v1.5.9` (Live) | `v1.5.3` (`.bak`) |
|---|---|---|
| File Size (Bytes) | `1041336` | `985896` |
| SHA-256 | `0bbe6d48f45fc155f1c1d029df8de67f221b7329010164eda2dd06d7978340b9` | `b8f03456397d455a63ac36593acc5463fe99287b4088a141b3cb59be54c901f6` |
| `EntryRVA` / `SizeOfImage` | `0x83840` / `0x103000` | `0x74200` / `0xf3000` |
| Section Count | `7` (`.tls` present) | `6` |
| `tbs.dll` / `ncrypt.dll` Imports | `5` / `4` | `5` / `4` |
| `ws2_32.dll` / `crypt32.dll` Imports | `25` / `15` | `25` / `15` |

### 4. `EOSSDK-Win64-Shipping.dll` Anti-Cheat Exports (`27` Client, `28` Server)

| Export Name | Ordinal | RVA |
|---|---|---|
| `EOS_AntiCheatClient_AddNotifyMessageToServer` | `30` | `0x0e74c00` |
| `EOS_AntiCheatClient_RemoveNotifyMessageToServer` | `47` | `0x0e74c70` |
| `EOS_AntiCheatClient_AddNotifyMessageToPeer` | `29` | `0x0e74cd0` |
| `EOS_AntiCheatClient_RemoveNotifyMessageToPeer` | `46` | `0x0e74d40` |
| `EOS_AntiCheatClient_AddNotifyPeerActionRequired` | `31` | `0x0e74da0` |
| `EOS_AntiCheatClient_RemoveNotifyPeerActionRequired` | `48` | `0x0e74e10` |
| `EOS_AntiCheatClient_AddNotifyPeerAuthStatusChanged` | `32` | `0x0e74e70` |
| `EOS_AntiCheatClient_RemoveNotifyPeerAuthStatusChanged` | `49` | `0x0e74ee0` |
| `EOS_AntiCheatClient_AddNotifyClientIntegrityViolated` | `28` | `0x0e74f40` |
| `EOS_AntiCheatClient_RemoveNotifyClientIntegrityViolated` | `45` | `0x0e74fb0` |
| `EOS_AntiCheatClient_BeginSession` | `33` | `0x0e75010` |
| `EOS_AntiCheatClient_EndSession` | `34` | `0x0e75080` |
| `EOS_AntiCheatClient_PollStatus` | `40` | `0x0e750f0` |
| `EOS_AntiCheatClient_GetSystemConfig` | `38` | `0x0e75160` |
| `EOS_AntiCheatClient_Reserved02` | `50` | `0x0e751d0` |
| `EOS_AntiCheatClient_GetModuleBuildId` | `35` | `0x0e75240` |
| `EOS_AntiCheatClient_GetSystemRequirementStatus` | `39` | `0x0e752b0` |
| `EOS_AntiCheatClient_GetPersistentSetting` | `36` | `0x0e75330` |
| `EOS_AntiCheatClient_SetPersistentSetting` | `51` | `0x0e753a0` |
| `EOS_AntiCheatClient_AddExternalIntegrityCatalog` | `27` | `0x0e75410` |
| `EOS_AntiCheatClient_ReceiveMessageFromServer` | `43` | `0x0e75480` |
| `EOS_AntiCheatClient_GetProtectMessageOutputLength` | `37` | `0x0e754f0` |
| `EOS_AntiCheatClient_ProtectMessage` | `41` | `0x0e75560` |
| `EOS_AntiCheatClient_UnprotectMessage` | `52` | `0x0e755e0` |
| `EOS_AntiCheatClient_RegisterPeer` | `44` | `0x0e75660` |
| `EOS_AntiCheatClient_UnregisterPeer` | `53` | `0x0e756d0` |
| `EOS_AntiCheatClient_ReceiveMessageFromPeer` | `42` | `0x0e75740` |

