# EAC EOS Cross-Build RVA Reference for Emulation & Static Analysis

Verified on disk (`2026-11-25`) via `build\eac_inspector.exe --generate-report` (`34/34` byte checks passed, exit `0`) and `devirt\devirt_runner.py` (`843` instructions traced across `6` Unicorn x86_64 suites, exit `0`).

## 1. Analyzed Driver Images & Measured Provenance

| Build Key | Path | Size (Bytes) | `ImageBase` | `SizeOfImage` | `EntryRVA` | `TimeDateStamp` | `.pdata` | SHA-256 |
|---|---|---|---|---|---|---|---|---|
| `eos_live` | `C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys` | `46,171,808` | `0x140000000` | `0x2C57000` | `0x27C438` | `0x6AFBE7DD` | `5,602` | `3eabcfe97e8a2bde0b3db1ab1645c66c8183f053588699d3409d93d2235c5d2b` |
| `eac_dumped` | `C:\Users\Administrator\Downloads\eac_dumped.sys` | `40,251,392` | `0xFFFFF80496FE0000` | `0x2663000` | `0x26AEB8` | `0x6AF4266C` | `5,545` | `7dbd776dd7ba7a5fbd33be53829f02d0df6212ff57bcee9b2456e365d5deddd2` |
| `eacfn` | `C:\Users\Administrator\Downloads\eacfn.sys` | `43,213,824` | `0xFFFFF80400000000` | `0x2937000` | `0x266478` | `0x6ABFFE92` | `5,556` | `c5ee0a9cf392feef75b88025bdfc7634276165969ee8b422eef78ffef6b09fd0` |
| `eos_prior` | `C:\Users\Administrator\Downloads\EasyAntiCheat_EOS.sys` | `44,398,752` | `0x140000000` | `0x2AA6000` | `0x255638` | `0x6A86EBF5` | `5,470` | `4e566f772c4c78066eba0187a276e10618312c63d766e0bd1c0a9d782256f734` |

## 2. Kernel Section Ranges

| Build Key | `.text` (`Sec[0]`) | `.rdata` (`Sec[1]`) | `.data` (`Sec[2]`) | `Sec[6]` (Exec Stub) | `Sec[7]` (Flattened / MBA) | `.pdata` (`Sec[8]`) | `.bearimp` (`Sec[9]`) |
|---|---|---|---|---|---|---|---|
| `eos_live` | `0x1000..0x27C464` | `0x27D000..0x326834` | `0x327000..0x377D30` | `0x385000..0x38CC00` | `0x38D000..0x2C46000` | `0x2C46000..0x2C57000` | None |
| `eac_dumped` | `0x1000..0x26AEE4` | `0x26B000..0x312924` | `0x313000..0x363D00` | `0x371000..0x378A00` | `0x379000..0x2652000` | `0x2652000..0x2663000` | None |
| `eacfn` | `0x1000..0x2664A4` | `0x267000..0x30B00C` | `0x30C000..0x35CFF4` | `0x36A000..0x372600` | `0x373000..0x2924000` | `0x2924000..0x2935000` | `0x2935000..0x29362DB` |
| `eos_prior` | `0x1000..0x255664` | `0x256000..0x2F75A4` | `0x2F8000..0x348B30` | `0x355000..0x35C600` | `0x35D000..0x2A95000` | `0x2A95000..0x2AA6000` | None |

## 3. `GsDriverEntry` -> `__security_init_cookie` -> `Sec[7]` Bootstrap

Every build enters `GsDriverEntry`, validates `.data` `__security_cookie` against `0` and default `0x00002B992DDFA232` (triggering `int 0x29` `FAST_FAIL_STACK_COOKIE_CHECK_FAILURE` on match, so emulators must initialize `__security_cookie` to a non-default value), writes `~cookie` to `cookie_rva + 8`, and jumps through a 5-byte `.text` thunk directly into `Sec[7]`:

| Build Key | `GsDriverEntry` (`EntryRVA`) | `__security_init_cookie` RVA | `.data` `__security_cookie` RVA | Real Init Thunk RVA | `Sec[7]` Entry Target RVA | `Sec[7]` Context Save Call | Static `FltRegisterFilter` IAT RVA |
|---|---|---|---|---|---|---|---|
| `eos_live` | `0x27C438` | `0x27C408` | `0x327188` | `0x17D881` | `0x46E812` | `0x38D063` | `0x31DE78` |
| `eac_dumped` | `0x26AEB8` | `0x26AE88` | `0x313188` | `0x1FD1A9` | `0x449896` | `0x379005` | `0x309FF0` |
| `eacfn` | `0x266478` | `0x266448` | `0x30C218` | `0x0416C8` | `0x4449F3` | `0x37300A` | `0x302890` |
| `eos_prior` | `0x255638` | `0x255608` | `0x2F8190` | `0x13E76C` | `0x403E73` | `0x35D280` | `0x2EFF70` |

## 4. Storage & SMART IOCTL Dispatch Sites

| IOCTL | Code | Build Key | Handler Entry RVA | Opcode / Store RVA | `.rdata` 16B Template RVA | Completion Callback RVA | `Sec[7]` Continuation RVA |
|---|---|---|---|---|---|---|---|
| `IOCTL_STORAGE_QUERY_PROPERTY` | `0x2D1400` | `eos_live` | `0x2A57ECA` (`0x2A57EE0`, `Sec[7]`) | `0x2A57F24` (`c7 46 30 00 14 2d 00`) | `0x2D6B2D` | `0x221EA9` | `0x45748F` -> `0x21351B0` |
| `IOCTL_STORAGE_QUERY_PROPERTY` | `0x2D1400` | `eac_dumped` | `0x153938` (`0x153955`, `.text`) | `0x153995` (`41 c7 40 30 00 14 2d 00`) | `0x2C605F` | `0x184960` | `0x394CEA` / `0x394CF1` -> `0x135950E` |
| `IOCTL_STORAGE_QUERY_PROPERTY` | `0x2D1400` | `eacfn` | `0x0B90A3` (`0x0B90BC`, `.text`) | `0x0B90FC` (`41 c7 40 30 00 14 2d 00`) | `0x2C25F9` | `0x215101` | `0x41D1D5` / `0x41D1DD` -> `0x121E832` |
| `SMART_RCV_DRIVE_DATA` | `0x07C088` | `eos_prior` | `0x8A292E` (`Sec[7]`) | `0x8A3B36` (`45 8d 88 c0 07 00 00`, `lea r9d, [r8+0x7c0]`) | N/A | N/A | `0x3E1632` / `0x408562` |
| `SMART_SEND_DRIVE_COMMAND` | `0x07C084` | `eacfn` | `0x1CD7A15` (`Sec[7]`) | `0x1CD7A24` (`48 8d 88 84 c0 07 00`, `lea rcx, [rax+0x7c084]`) | N/A | N/A | `0x3CB732` |

## 5. Disk, Partition, Optical, LUN, & MAC Formatter XREFs in `.text`

| Item | `eos_live` (`46.17 MB`) | `eac_dumped` (`40.25 MB`) | `eacfn` (`43.21 MB`) | `eos_prior` (`44.40 MB`) |
|---|---|---|---|---|
| Enclosing `.pdata` Function | `0x1D9C7D..0x1DB577` | `0x5C9F5..0x5E36F` | `0x15BC92..0x15D68E` | `0x108E6D..0x10A737` |
| Prologue `K_state` `C_MIX` | `0xFF51AFD7ED558CCD` (`0x1D9CA2`) | `0xBF58476D1CE4E5B9` (`0x5CA1B`) | `0x15BCB8` prologue | `0x108E93` prologue |
| `MBR:%08x` (`.text` XREF / `.rdata` UTF-16LE) | `0x1DB3B3` / `0x31D146` | `0x5E1C2` / `0x3092B6` | `0x15D4C8` / `0x301B5E` | `0x10A577` / `0x2EF232` |
| `Part:%u` (`.text` XREF / `.rdata` UTF-16LE) | `0x1DB412` / `0x31D224` | `0x5E21F` / `0x309394` | `0x15D52E` / `0x301C3C` | `0x10A5DC` / `0x2EF310` |
| `CD:%u` (`.text` XREF / `.rdata` UTF-16LE) | `0x1DA35E` / `0x31D234` | `0x5D0F3` / `0x3093A4` | `0x15C360` / `0x301C4C` | `0x1094F8` / `0x2EF320` |
| `:lun=%llx` (`.text` XREF / `.rdata` UTF-16LE) | `0x1DB047` / `0x31D132` | `0x5DE74` / `0x3092A2` | `0x15D157` / `0x301B4A` | `0x10A233` / `0x2EF21E` |
| `%02x:%02x:%02x:%02x:%02x:%02x` (`.text` / `.rdata`) | `0x1DADE9` / `0x31D1E8` | `0x5DBEE` / `0x309358` | `0x15CEBF` / `0x301C00` | `0x109FA7` / `0x2EF2D4` |

## 6. SMBIOS `'RSMB'` Templates & `.bearimp` Kernel API Slots

All four builds embed a 20-byte `SYSTEM_FIRMWARE_TABLE_INFORMATION` header (`42 4D 53 52 01 00 00 00 ...`, `ProviderSignature = 'RSMB'`, `Action = SystemFirmwareTable_Get = 1`) in `.rdata`:
- `eos_live`: `RVA 0x303B74`
- `eac_dumped`: `RVA 0x2D458C`
- `eacfn`: `RVA 0x2C5C8C`
- `eos_prior`: `RVA 0x2BE27C`

`eacfn.sys` `.bearimp` (`RVA 0x2935000..0x29362DB`, `119` reconstructed imports: `1` `FLTMGR.SYS`, `114` `ntoskrnl.exe`, `4` `msrpc.sys`) resolves the target kernel routines invoked through encrypted pointer tables:
- `ntoskrnl.exe!NtQuerySystemInformation` (`0x29354C0`), `NtQuerySystemInformationEx` (`0x29355D0`)
- `ntoskrnl.exe!HalAcpiGetTableEx` (`0x2935548`), `HalGetBusDataByOffset` (`0x2935550`)
- `ntoskrnl.exe!IoGetDeviceInterfaces` (`0x2935658`), `IoWMIOpenBlock` (`0x2935560`)
- `ntoskrnl.exe!NtQueryLicenseValue` (`0x2935718`), `NtQuerySystemEnvironmentValueEx` (`0x2935720`)
- `ntoskrnl.exe!MmGetPhysicalAddress` (`0x2935468`), `MmMapIoSpaceEx` (`0x2935470`), `MmCopyMemory` (`0x29356C0`)

## 7. `KUSER_SHARED_DATA` (`0xFFFFF78000000000`) Reads (Verified DDK Fields & Exact `movabs` Starts)

Every RVA below is the exact 10-byte `movabs reg64, 0xFFFFF78000000xxx` opcode boundary (`48/49 B8..BF`). Struct member offsets were verified directly against `C:\msys64\ucrt64\include\ddk\ntddk.h` (`_KUSER_SHARED_DATA`) and instruction-level operand widths:
- `+0x274` is `BOOLEAN ProcessorFeatures[64]` (`+0x274..+0x2B3`, passed by base pointer to a 64-byte feature hash/copy helper via `call r10`), NOT `KdDebuggerEnabled` (`KdDebuggerEnabled` is at `+0x2D4`).
- `+0x2EC` is `BOOLEAN SafeBootMode` (read via `movabs rax, 0xFFFFF780000002EC; mov al, byte ptr [rax]; ret`), NOT `ConsoleSessionForegroundProcessId` (`+0x338`).

| Offset | Verified `_KUSER_SHARED_DATA` Field | `eos_live` RVAs | `eac_dumped` RVAs | `eacfn` RVAs | `eos_prior` RVAs |
|---|---|---|---|---|---|
| `+0x008` | `InterruptTime` (`KSYSTEM_TIME`) | `0xCCCBE`, `0x1017A3`, `0x1426D7E` (`Sec[7]`), `0x184EC74` (`Sec[7]`), `0x1B4B3AE` (`Sec[7]`) | `0x4CF6B`, `0x15187B`, `0x17AA7C`, `0xE5AF85` (`Sec[7]`), `0x19B87DB` (`Sec[7]`) | `0x4E032`, `0x13C959`, `0x146022`, `0x1F71D8D` (`Sec[7]`), `0x2141F52` (`Sec[7]`) | `0xCABBB`, `0x147E42`, `0x1F100C`, `0x16C53C4` (`Sec[7]`) |
| `+0x014` | `SystemTime` (`KSYSTEM_TIME`) | `0xCCA5B`, `0xF794B`, `0x157415`, `0x171B6A`, `0x133126F` (`Sec[7]`), `0x15A9D1A` (`Sec[7]`), `0x1EE86F8` (`Sec[7]`), `0x1F85742` (`Sec[7]`) | `0x171FE2`, `0x17A827`, `0x1B286A`, `0x1CD486`, `0x1F2A10`, `0x12DB663` (`Sec[7]`), `0x151B4C7` (`Sec[7]`), `0x186E71D` (`Sec[7]`), `0x21D5096` (`Sec[7]`) | `0x4DDE3`, `0x9A2E1`, `0xA590D`, `0x1C6C32`, `0x126C56E` (`Sec[7]`), `0x1317748` (`Sec[7]`), `0x1AA87DE` (`Sec[7]`), `0x216822E` (`Sec[7]`) | `0x105CF9`, `0x1DC687`, `0x1EB817`, `0x1F937A`, `0x17E776A` (`Sec[7]`), `0x17F8753` (`Sec[7]`), `0x1D83B27` (`Sec[7]`), `0x2914C1A` (`Sec[7]`) |
| `+0x020` | `TimeZoneBias` (`KSYSTEM_TIME`) | `0x1E12EB`, `0x1ADA0B1` (`Sec[7]`) | `0x1C95B8A` (`Sec[7]`), `0x25ADDE3` (`Sec[7]`) | `0x15E8E6C` (`Sec[7]`), `0x1FBF7CB` (`Sec[7]`) | `0x13143F`, `0x1A0073` |
| `+0x260` | `NtBuildNumber` (`ULONG`) | `0x542CC`, `0x1D1A48`, `0x18D420D` (`Sec[7]`), `0x234DDD5` (`Sec[7]`) | `0x0F59A`, `0x149AAF`, `0x21EFF0`, `0x18717D8` (`Sec[7]`), `0x1871824` (`Sec[7]`) | `0x8D2FC`, `0x1CB13B`, `0x1B02C4E` (`Sec[7]`), `0x2364242` (`Sec[7]`), `0x23642BB` (`Sec[7]`) | `0x1360D0`, `0x207E6D`, `0x187B391` (`Sec[7]`) |
| `+0x274` | `ProcessorFeatures[0..63]` (`BOOLEAN[64]`) | `0xEFC8B` | `0x2091C8` | `0x2100DE` | `0x1B11B9` |
| `+0x2EC` | `SafeBootMode` (`BOOLEAN`) | `0x1D19B7` | `0x21EF4E` | `0x1CB08C` | `0x207DCA` |
| `+0x320` | `TickCount` (`KSYSTEM_TIME`) | `0xAD4E1`, `0xCC95C`, `0x145EC8`, `0x1C0AD5` | `0x342ED`, `0x17A739`, `0x19FEC4`, `0xF1EA30` (`Sec[7]`) | `0x370A3`, `0x4DCF5`, `0x1EFC7E`, `0x1BD9DC8` (`Sec[7]`) | `0xDB729`, `0x151B35`, `0x187003`, `0x1F9289` |

## 8. `CPUID` & Per-Call Affine Pointer Decryption Summary

| Build Key | `.text` `cpuid` Sites | `Sec[7]` `cpuid` Sites | `.text` Affine Decrypt Sequences | Direct Call-Thunk Subset | Unique Encrypted `.rdata` Slots | Encrypted Slot RVA Span |
|---|---|---|---|---|---|---|
| `eos_live` | `30` | `99` | `1,819` | `954` | `908` | `0x313808..0x31C610` |
| `eac_dumped` | `27` | `83` | `1,806` | `953` | `911` | `0x2FFA08..0x3088B8` |
| `eacfn` | `30` | `61` | `1,790` | `958` | `915` | `0x2F8370..0x300DF0` |
| `eos_prior` | `29` | `84` | `1,769` | `955` | `913` | `0x2E6378..0x2EEF40` |

Closed-form prologue key derivation (`derive_prologue_kstate`, verified bit-exact against Unicorn emulation `0x4F6A41A016546856 == 0x4F6A41A016546856`):
```c
uint64_t t = caller_seed * C_MIX;
uint64_t K_state = ((t ^ ((t >> 32) >> ((t >> 60) & 0x3F))) * C_MIX) ^ caller_seed;
uint64_t target_va = *(uint64_t*)(ImageBase + SlotRVA) - (C_MUL * K_state);
```

## 9. Usermode Service (`EasyAntiCheat_EOS.exe` v1.5.9), Launcher, & `EOSSDK`

- **Shared Section & Rolling Cipher (`0x004243c0..0x00424a0d`)**: `Global\EasyAntiCheat_EOSBin` (`96 MB`), events `Global\EasyAntiCheat_EOSEvent{Module,Driver,Game}`, rolling byte cipher at `VA 0x0042499a..0x00424a0d` (exact C++20 forward/inverse verified in `src/protocol_decoders.cpp` across `11` odd/even sizes).
- **TPM 2.0 EK & `EacQuoteKey` (`0x00423fd0..0x004240f7`, `0x004250a0..0x0042536f`, `0x004331d0..0x00433cc0`)**: Validates `TPM_VERSION_20` via `tbs.dll!Tbsi_GetDeviceInfo`, calls `TpmCoreProvisioning.dll!TpmRetrieveEkCertificate`, imports `Attestation\AttestationKey` (`Magic = 0x1EAC92F3`) via `'KPTM'` `PcpTpmPersistentKeyBlob`, writes `OpaqueKeyBlob` to `HKLM\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\EacQuoteKey` (`QuoteKeyStatus = 1..8`), and evicts on teardown with `TPM2_CC_EvictControl` (`0x00000120`) via `tbs.dll!Tbsip_Submit_Command`.
- **HTTPS Datarouter (`0x004101c0`, `0x00413160`, `0x00413440`)**: Static `libcurl` + Windows `Schannel` (`0` `CURLOPT_PINNEDPUBLICKEY` xrefs), `23` `EventName` IDs posted to `api.epicgames.dev` (`0x004b082c`) and `datarouter.ol.epicgames.com` (`0x004b08e0`).
- **`EOSSDK-Win64-Shipping.dll` (`ImageBase = 0x180000000`)**: `27` `EOS_AntiCheatClient_*` (`RVA 0x0E74C00..0x0E75740`, vtable `+0x00..+0xD0`) and `28` `EOS_AntiCheatServer_*` (`RVA 0x0E757B0..0x0E76360`) exports. Full table in `EOSSDK_AND_LAUNCHER.md`.
