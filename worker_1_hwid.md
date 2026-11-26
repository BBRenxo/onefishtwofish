# Worker 1 Report: EAC EOS Kernel Drivers (`EasyAntiCheat_EOS.sys`, `eac_dumped.sys`, `eacfn.sys`) HWID & Telemetry Sites

## Target Metadata & Section Layout

Four kernel driver images were inspected and cross-verified on disk:

1. **Live Production Driver (`EasyAntiCheat_EOS.sys` — Updated 2026-11-25)**:
   - **Path**: `C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys`
   - **Size**: `46,171,808` bytes
   - **PE Headers**: `ImageBase = 0x140000000`, `SizeOfImage = 0x2C57000`, `EntryRVA = 0x27C438`, `TimeDateStamp = 0x6AFBE7DD`, `.pdata` functions = `5,602`
   - **Section Table**:
     - `Sec[0]` `.text`: `RVA 0x1000..0x27C464` (`VirtualSize = 0x27B464`, `RawPtr = 0x400`, `RawSize = 0x27B600`)
     - `Sec[1]` `.rdata`: `RVA 0x27D000..0x326834` (`VirtualSize = 0xA9834`, `RawPtr = 0x27BA00`, `RawSize = 0xA9A00`)
     - `Sec[2]` `.data`: `RVA 0x327000..0x377D30` (`VirtualSize = 0x50D30`, `RawPtr = 0x325400`, `RawSize = 0x2200`)
     - `Sec[6]` `""` (exec stub): `RVA 0x385000..0x38CC00` (`VirtualSize = 0x7C00`, `RawPtr = 0x332C00`)
     - `Sec[7]` `""` (VM / flattened continuation region): `RVA 0x38D000..0x2C46000` (`VirtualSize = 0x28B9000` / `42,700,800` bytes, `RawPtr = 0x33A800`, `RawSize = 0x28B8400`, `Chars = 0x68000000`)
     - `Sec[8]` `.pdata`: `RVA 0x2C46000..0x2C57000` (`VirtualSize = 0x11000`, `RawPtr = 0x2BF2C00`)

2. **Live Kernel Memory Dump (`eac_dumped.sys`)**:
   - **Path**: `C:\Users\Administrator\Downloads\eac_dumped.sys`
   - **Size**: `40,251,392` bytes
   - **PE Headers**: `ImageBase = 0xFFFFF80496FE0000`, `SizeOfImage = 0x2663000`, `EntryRVA = 0x26AEB8`, `TimeDateStamp = 0x6AF4266C`, `.pdata` functions = `5,545`
   - **Section Table**:
     - `Sec[0]` `.text`: `RVA 0x1000..0x26AEE4` (`VirtualSize = 0x269EE4`, `RawPtr = 0x1000`)
     - `Sec[1]` `.rdata`: `RVA 0x26B000..0x312924` (`VirtualSize = 0xA7924`, `RawPtr = 0x26B000`)
     - `Sec[2]` `.data`: `RVA 0x313000..0x363D00` (`VirtualSize = 0x50D00`, `RawPtr = 0x313000`, `6,423` populated runtime qwords)
     - `Sec[6]` `""` (exec stub): `RVA 0x371000..0x378A00` (`VirtualSize = 0x7A00`)
     - `Sec[7]` `""` (VM / flattened continuation region): `RVA 0x379000..0x2652000` (`VirtualSize = 0x22D9000` / `36,540,416` bytes, `RawPtr = 0x379000`, `Chars = 0x68000000`)
     - `Sec[8]` `.pdata`: `RVA 0x2652000..0x2663000` (`VirtualSize = 0x11000`)

3. **Fortnite Import-Reconstructed Build (`eacfn.sys`)**:
   - **Path**: `C:\Users\Administrator\Downloads\eacfn.sys`
   - **Size**: `43,213,824` bytes
   - **PE Headers**: `ImageBase = 0xFFFFF80400000000`, `SizeOfImage = 0x2937000`, `EntryRVA = 0x266478`, `TimeDateStamp = 0x6ABFFE92`, `.pdata` functions = `5,556`
   - **Section Table**:
     - `Sec[0]` `.text`: `RVA 0x1000..0x2664A4` (`VirtualSize = 0x2654A4`, `RawPtr = 0x1000`)
     - `Sec[1]` `.rdata`: `RVA 0x267000..0x30B00C` (`VirtualSize = 0xA400C`, `RawPtr = 0x267000`)
     - `Sec[2]` `.data`: `RVA 0x30C000..0x35CFF4` (`VirtualSize = 0x50FF4`, `RawPtr = 0x30C000`)
     - `Sec[6]` `""` (exec stub): `RVA 0x36A000..0x372600` (`VirtualSize = 0x8600`)
     - `Sec[7]` `""` (VM / flattened continuation region): `RVA 0x373000..0x2924000` (`VirtualSize = 0x25B1000` / `39,522,304` bytes, `RawPtr = 0x373000`, `Chars = 0x68000000`)
     - `Sec[8]` `.pdata`: `RVA 0x2924000..0x2935000` (`VirtualSize = 0x11000`)
     - `Sec[9]` `.bearimp`: `RVA 0x2935000..0x29362DB` (`VirtualSize = 0x12DB`, reconstructed import table listing `1` `FLTMGR.SYS`, `114` `ntoskrnl.exe`, and `4` `msrpc.sys` imports)

4. **Prior Archived Driver Build (`Downloads\EasyAntiCheat_EOS.sys`)**:
   - **Path**: `C:\Users\Administrator\Downloads\EasyAntiCheat_EOS.sys` ( note: `AppData\Roaming\EasyAntiCheat\prod-fn\62a9473a2dca46b29ccf17577fcf42d7\EasyAntiCheat_EOS.sys` is no longer present on disk )
   - **Size**: `44,398,752` bytes
   - **PE Headers**: `ImageBase = 0x140000000`, `SizeOfImage = 0x2AA6000`, `EntryRVA = 0x255638`, `TimeDateStamp = 0x6A86EBF5`, `.pdata` functions = `5,470`
   - **Section Table**: `Sec[0]` `.text` `0x1000..0x255664`, `Sec[1]` `.rdata` `0x256000..0x2F75A4`, `Sec[2]` `.data` `0x2F8000..0x348B30`, `Sec[7]` `0x35D000..0x2A95000`, `Sec[8]` `.pdata` `0x2A95000..0x2AA6000`.

---

## Dynamic Import Decryption & Pointer Table Architecture

- **Static IAT**: On-disk `EasyAntiCheat_EOS.sys` builds and `eac_dumped.sys` statically import only `FLTMGR.SYS!FltRegisterFilter`:
  - `Program Files\EasyAntiCheat_EOS.sys`: IAT RVA `0x31DE78`
  - `eac_dumped.sys`: IAT RVA `0x309FF0`
  - `eacfn.sys`: IAT RVA `0x302890`
  - `Downloads\EasyAntiCheat_EOS.sys`: IAT RVA `0x2EFF70`
- **Reconstructed Kernel Import Inventory (`eacfn.sys` `.bearimp`, `RVA 0x2935000..0x29362DB`)**:
  - `ntoskrnl.exe` (`114` functions at FirstThunk `RVA 0x2935430..0x29357B8`): includes `NtQuerySystemInformation` (`0x29354C0`), `NtQuerySystemInformationEx` (`0x29355D0`), `HalAcpiGetTableEx` (`0x2935548`), `HalGetBusDataByOffset` (`0x2935550`), `IoGetDeviceInterfaces` (`0x2935658`), `IoWMIOpenBlock` (`0x2935560`), `NtQuerySystemEnvironmentValueEx` (`0x2935720`), `NtQueryLicenseValue` (`0x2935718`), `MmGetPhysicalAddress` (`0x2935468`), `MmMapIoSpaceEx` (`0x2935470`), `MmCopyMemory` (`0x29356C0`), `KeStackAttachProcess` (`0x2935458`), `ObOpenObjectByName` (`0x2935730`), `_vsnwprintf` (`0x29357A8`), `KeQuerySystemTimePrecise` (`0x29357B0`), `IofCompleteRequest` (`0x29357B8`).
  - `msrpc.sys` (`4` functions at FirstThunk `RVA 0x2936260..0x2936278`): `RpcAsyncInitializeHandle`, `RpcBindingBind`, `RpcBindingCreateW`, `RpcBindingFree`.
- **Per-Call Affine Pointer Decryption Mechanism**:
  - Neither `.text` nor `Sec[7]` calls `.bearimp` directly (`0` direct RIP-relative references to `0x2935000..0x29362DB`). Instead, every external routine or internal helper is dispatched via an encrypted table in `.rdata`/`.data` using a per-function 64-bit MurmurHash3-style mixed state key (`K_state` held in `r12`, `rbp`, `rbx`, or `[rsp+0xA0]`):
    1. **Prologue Key Derivation** (e.g., `eac_dumped.sys` `RVA 0x5CA1B..0x5CA44`, `Program Files\EasyAntiCheat_EOS.sys` `RVA 0x1D9CA2..0x1D9CCB`, `eacfn.sys` `RVA 0x15BCB8..0x15BCE8`):
       ```c
       uint64_t t = caller_seed * C_MIX; // e.g. C_MIX = 0xBF58476D1CE4E5B9 in eac_dumped.sys
       uint64_t K_state = ((t ^ ((t >> 32) >> (t >> 60))) * C_MIX) ^ caller_seed;
       ```
    2. **Call-Site Target Decryption** (`movabs rax, C_MUL; imul rax, K_state; mov r10, [rip + disp32]; sub r10, rax; call r10`):
       - `Program Files\EasyAntiCheat_EOS.sys` (`RVA 0x1DB39B..0x1DB3C2`): `r10 = *(uint64_t*)(ImageBase + 0x317528) - (0xDEB79555249276ABULL * rbp)`
       - `eac_dumped.sys` (`RVA 0x5E1AA..0x5E1D1`): `r10 = *(uint64_t*)(ImageBase + 0x300950) - (0x92CB24A8F9E23650ULL * r12)` (live slot `0x300950` holds `0xF43EFC364F9CB7F6`, slot `0x300948` holds `0x75855CA8B84FE912`)
       - `eacfn.sys` (`RVA 0x15D4B0..0x15D4D7`): `r10 = *(uint64_t*)(ImageBase + 0x2FB320) - (0x5909A7E61A7F8D54ULL * rdx)` (slot `0x2FB320` holds `0x0659D1082E32CC5A`, slot `0x2FB318` holds `0xE5823FE995E867CF`)
       - `Downloads\EasyAntiCheat_EOS.sys` (`RVA 0x10A55F..0x10A586`): `r10 = *(uint64_t*)(ImageBase + 0x2E9478) - (0xB9E1C589B282CC70ULL * rbx)`

---

## 1. Disk Serial (`IOCTL_STORAGE_QUERY_PROPERTY`, `SMART_RCV_DRIVE_DATA`, Partition/MBR)

### Site A: `IOCTL_STORAGE_QUERY_PROPERTY` (`0x2D1400`)

Across all three builds containing the unobfuscated `0x2D1400` dispatch block (`Program Files\EasyAntiCheat_EOS.sys`, `eac_dumped.sys`, `eacfn.sys`), the handler populates a `STORAGE_PROPERTY_QUERY` buffer (`0x2800000000`, `0x200`) and sets up the IRP `IO_STACK_LOCATION` with `IoControlCode = 0x2D1400` (`IOCTL_STORAGE_QUERY_PROPERTY`), `OutputBufferLength = 0x1030`, and a completion callback before saving registers into the `[r12 + offset]` virtual frame and jumping into `Sec[7]`:

| Driver Build | Block Entry RVA | `0x2D1400` Store RVA | Completion Callback RVA | `Sec[7]` Jump Target RVA |
|---|---|---|---|---|
| `Program Files\EasyAntiCheat_EOS.sys` (`2026-11-25`, in `Sec[7]`) | `0x2A57EE0` | `0x2A57F24` | `0x221EA9` | `0x45748F` |
| `eac_dumped.sys` (in `.text`) | `0x153955` | `0x153995` | `0x184960` | `0x394CEA` |
| `eacfn.sys` (in `.text`) | `0xB90BC` | `0xB90FC` | `0x215101` | `0x41D1D5` |
| `Downloads\EasyAntiCheat_EOS.sys` (`2026-11-24`) | `UNKNOWN` (obfuscated in `Sec[7]`) | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` |

#### 1. `Program Files\EasyAntiCheat_EOS.sys` (`RVA 0x2A57EE0..0x2A57F71`, inside `Sec[7]`)
- `0x2A57EE0`: `8b 84 24 b8 00 00 00` — `mov eax, dword ptr [rsp + 0xb8]`
- `0x2A57EE7`: `48 bf 29 ad 37 80 07 46 6c 9b` — `movabs rdi, 0x9b6c46078037ad29`
- `0x2A57EF1`: `49 33 7c 24 48` — `xor rdi, qword ptr [r12 + 0x48]`
- `0x2A57EF6`: `41 8b 9c 24 f0 00 00 00` — `mov ebx, dword ptr [r12 + 0xf0]`
- `0x2A57EFE`: `0f 10 80 2d 6b 2d 00` — `movups xmm0, xmmword ptr [rax + 0x2d6b2d]` (`rax = ImageBase`)
- `0x2A57F05`: `0f 11 01` — `movups xmmword ptr [rcx], xmm0`
- `0x2A57F08`: `89 59 10` — `mov dword ptr [rcx + 0x10], ebx`
- `0x2A57F0B`: `49 b8 00 00 00 00 28 00 00 00` — `movabs r8, 0x2800000000`
- `0x2A57F15`: `4c 89 41 14` — `mov qword ptr [rcx + 0x14], r8`
- `0x2A57F19`: `c7 41 1c 00 02 00 00` — `mov dword ptr [rcx + 0x1c], 0x200`
- `0x2A57F20`: `48 89 56 20` — `mov qword ptr [rsi + 0x20], rdx`
- `0x2A57F24`: `c7 46 30 00 14 2d 00` — `mov dword ptr [rsi + 0x30], 0x2d1400` (`IOCTL_STORAGE_QUERY_PROPERTY`)
- `0x2A57F2B`: `c7 46 28 30 10 00 00` — `mov dword ptr [rsi + 0x28], 0x1030` (`OutputBufferLength`)
- `0x2A57F32`: `48 8d 90 a9 1e 22 00` — `lea rdx, [rax + 0x221ea9]`
- `0x2A57F39`: `48 89 56 08` — `mov qword ptr [rsi + 8], rdx`
- `0x2A57F3D..0x2A57F63`: Saves context into `[r12]`, `[r12+0x28]`, `[r12+0xE0]=0x1030`, `[r12+0xE8]`, `[r12+0x158]`, `[r12+0x168]`.
- `0x2A57F6B`: `48 05 8f 74 45 00` — `add rax, 0x45748f`
- `0x2A57F71`: `ff e0` — `jmp rax` (jumps to `Sec[7]` `RVA 0x45748F`)

#### 2. `eac_dumped.sys` (`RVA 0x153955..0x1539E2`, in `.text`)
- `0x153955`: `48 bf 76 a9 53 bd cb 77 cd 1a` — `movabs rdi, 0x1acd77cbbd53a976`
- `0x15395F`: `49 33 bc 24 50 01 00 00` — `xor rdi, qword ptr [r12 + 0x150]`
- `0x153967`: `4d 8b 84 24 88 01 00 00` — `mov r8, qword ptr [r12 + 0x188]`
- `0x15396F`: `0f 10 80 5f 60 2c 00` — `movups xmm0, xmmword ptr [rax + 0x2c605f]`
- `0x153976`: `0f 11 06` — `movups xmmword ptr [rsi], xmm0`
- `0x153979`: `89 56 10` — `mov dword ptr [rsi + 0x10], edx`
- `0x15397C`: `48 ba 00 00 00 00 28 00 00 00` — `movabs rdx, 0x2800000000`
- `0x153986`: `48 89 56 14` — `mov qword ptr [rsi + 0x14], rdx`
- `0x15398A`: `c7 46 1c 00 02 00 00` — `mov dword ptr [rsi + 0x1c], 0x200`
- `0x153991`: `49 89 78 20` — `mov qword ptr [r8 + 0x20], rdi`
- `0x153995`: `41 c7 40 30 00 14 2d 00` — `mov dword ptr [r8 + 0x30], 0x2d1400` (`IOCTL_STORAGE_QUERY_PROPERTY`)
- `0x15399D`: `41 c7 40 28 30 10 00 00` — `mov dword ptr [r8 + 0x28], 0x1030` (`OutputBufferLength`)
- `0x1539A5`: `48 8d 90 60 49 18 00` — `lea rdx, [rax + 0x184960]`
- `0x1539AC`: `49 89 50 08` — `mov qword ptr [r8 + 8], rdx`
- `0x1539B0..0x1539D4`: Saves context into `[r12+0x18]`, `[r12+0x38]`, `[r12+0x48]`, `[r12+0xA0]=0x1030`, `[r12+0x140]`, `[r12+0x160]`.
- `0x1539DC`: `48 05 ea 4c 39 00` — `add rax, 0x394cea`
- `0x1539E2`: `ff e0` — `jmp rax` (jumps to `Sec[7]` `RVA 0x394CEA`)

#### 3. `eacfn.sys` (`RVA 0xB90BC..0xB9152`, in `.text`)
- `0xB90BC`: `48 bf e7 6e 5a a8 54 46 59 27` — `movabs rdi, 0x27594654a85a6ee7`
- `0xB90C6`: `49 33 bc 24 50 01 00 00` — `xor rdi, qword ptr [r12 + 0x150]`
- `0xB90CE`: `4d 8b 84 24 68 01 00 00` — `mov r8, qword ptr [r12 + 0x168]`
- `0xB90D6`: `0f 10 80 f9 25 2c 00` — `movups xmm0, xmmword ptr [rax + 0x2c25f9]`
- `0xB90DD`: `0f 11 06` — `movups xmmword ptr [rsi], xmm0`
- `0xB90E0`: `89 4e 10` — `mov dword ptr [rsi + 0x10], ecx`
- `0xB90E3`: `48 b9 00 00 00 00 28 00 00 00` — `movabs rcx, 0x2800000000`
- `0xB90ED`: `48 89 4e 14` — `mov qword ptr [rsi + 0x14], rcx`
- `0xB90F1`: `c7 46 1c 00 02 00 00` — `mov dword ptr [rsi + 0x1c], 0x200`
- `0xB90F8`: `49 89 78 28` — `mov qword ptr [r8 + 0x28], rdi`
- `0xB90FC`: `41 c7 40 30 00 14 2d 00` — `mov dword ptr [r8 + 0x30], 0x2d1400` (`IOCTL_STORAGE_QUERY_PROPERTY`)
- `0xB9104`: `41 c7 40 20 30 10 00 00` — `mov dword ptr [r8 + 0x20], 0x1030` (`OutputBufferLength`)
- `0xB910C`: `48 8d 88 01 51 21 00` — `lea rcx, [rax + 0x215101]`
- `0xB9113`: `49 89 48 08` — `mov qword ptr [r8 + 8], rcx`
- `0xB9117..0xB9144`: Saves context into `[r12+0x88]`, `[r12+0xA0]`, `[r12+0xD0]`, `[r12+0xF8]`, `[r12+0x108]=0x1030`, `[r12+0x110]`.
- `0xB914C`: `48 05 d5 d1 41 00` — `add rax, 0x41d1d5`
- `0xB9152`: `ff e0` — `jmp rax` (jumps to `Sec[7]` `RVA 0x41D1D5`)

### Site B: `SMART_RCV_DRIVE_DATA` (`0x7C088`) — `Downloads\EasyAntiCheat_EOS.sys` `Sec[7]`
- **RVA / VA**: `0x8A3B36` / `0x1408A3B36` (`Downloads\EasyAntiCheat_EOS.sys`)
- **Raw Bytes & Disassembly**:
  - `0x8A3B36`: `45 8d 88 c0 07 00 00` — `lea r9d, [r8 + 0x7c0]` (obfuscated `0x7C088` construction inside `Sec[7]`)
  - `0x8A3B3D`: `41 81 e1 ff ff ff 00` — `and r9d, 0xffffff`
- In `Program Files\EasyAntiCheat_EOS.sys`, `eac_dumped.sys`, and `eacfn.sys`, the `0x7C088` constant is re-seeded inside `Sec[7]` (`UNKNOWN` statically).

### Site C: Disk MBR, Partition, Optical, & LUN Formatters

All four builds contain an identical disk/partition/MAC telemetry formatting function in `.text` (covered by `.pdata`):

| Item | `Program Files\EasyAntiCheat_EOS.sys` (`2026-11-25`) | `eac_dumped.sys` | `eacfn.sys` | `Downloads\EasyAntiCheat_EOS.sys` (`2026-11-24`) |
|---|---|---|---|---|
| Enclosing `.pdata` Function | `0x1D9C7D..0x1DB577` | `0x5C9F5..0x5E36F` | `0x15BC92..0x15D68E` | `0x108E6D..0x10A737` |
| `MBR:%08x` `.rdata` String RVA | `0x31D146` | `0x3092B6` | `0x301B5E` | `0x2EF232` |
| `MBR:%08x` `.text` LEA XREF RVA | `0x1DB3B3` (`4c 8d 05 8c 1d 14 00`) | `0x5E1C2` (`48 8d 15 ed b0 2a 00`) | `0x15D4C8` (`48 8d 15 8f 46 1a 00`) | `0x10A577` (`48 8d 0d b4 4c 1e 00`) |
| `Part:%u` `.rdata` String RVA | `0x31D224` | `0x309394` | `0x301C3C` | `0x2EF310` |
| `Part:%u` `.text` LEA XREF RVA | `0x1DB412` (`4c 8d 05 0b 1e 14 00`) | `0x5E21F` (`48 8d 15 6e b1 2a 00`) | `0x15D52E` (`48 8d 15 07 47 1a 00`) | `0x10A5DC` (`48 8d 0d 2d 4d 1e 00`) |
| `CD:%u` `.rdata` String RVA | `0x31D234` | `0x3093A4` | `0x301C4C` | `0x2EF320` |
| `CD:%u` `.text` LEA XREF RVA | `0x1DA35E` (`4c 8d 05 cf 2e 14 00`) | `0x5D0F3` (`48 8d 15 aa c2 2a 00`) | `0x15C360` (`48 8d 15 e5 58 1a 00`) | `0x1094F8` (`48 8d 0d 21 5e 1e 00`) |
| `:lun=%llx` `.rdata` String RVA | `0x31D132` | `0x3092A2` | `0x301B4A` | `0x2EF21E` |
| `:lun=%llx` `.text` LEA XREF RVA | `0x1DB047` (`4c 8d 05 e4 20 14 00`) | `0x5DE74` (`4c 8d 05 27 b4 2a 00`) | `0x15D157` (`4c 8d 05 ec 49 1a 00`) | `0x10A233` (`4c 8d 05 e4 4f 1e 00`) |

---

## 2. NIC MAC Address Formatting (`%02x:%02x:%02x:%02x:%02x:%02x`)

Inside the same hardware identifier formatting function, 6 MAC address bytes are pushed onto the stack (`[rsp+0x20]`..`[rsp+0x40]`) and formatted via the decrypted `_snwprintf_s` / `_vsnwprintf` pointer (`call r10`):

| Driver Build | `.rdata` String RVA | `.text` LEA XREF RVA | Vararg Setup Range | Raw LEA Bytes |
|---|---|---|---|---|
| `Program Files\EasyAntiCheat_EOS.sys` (`2026-11-25`) | `0x31D1E8` | `0x1DADE9` | `0x1DADD1..0x1DADE4` | `4c 8d 05 f8 23 14 00` (`lea r8, [rip + 0x1423f8]`) |
| `eac_dumped.sys` | `0x309358` | `0x5DBEE` | `0x5DBD7..0x5DBE9` | `4c 8d 05 63 b7 2a 00` (`lea r8, [rip + 0x2ab763]`) |
| `eacfn.sys` | `0x301C00` | `0x15CEBF` | `0x15CEAA..0x15CEB7` | `4c 8d 05 3a 4d 1a 00` (`lea r8, [rip + 0x1a4d3a]`) |
| `Downloads\EasyAntiCheat_EOS.sys` (`2026-11-24`) | `0x2EF2D4` | `0x109FA7` | `0x109F8F..0x109FA2` | `4c 8d 05 26 53 1e 00` (`lea r8, [rip + 0x1e5326]`) |

- Direct `\Device\Nsi` (`0x12001B`, `0x120007`) and `IOCTL_NDIS_QUERY_GLOBAL_STATS` (`0x170002`) constants have `0` unobfuscated hits in `.text` (`UNKNOWN` — constructed inside `Sec[7]`).

---

## 3. SMBIOS (`RSMB` / `SystemFirmwareTableInformation`)

All four builds store the 4-byte little-endian `'RSMB'` (`42 4d 53 52` = `0x52534D42`) provider signature in `.rdata` followed by `01 00 00 00` (`SystemFirmwareTable_Get = 1`) for `ntoskrnl!NtQuerySystemInformation` class `76` (`SystemFirmwareTableInformation`, verified in `eacfn.sys` `.bearimp` at `RVA 0x29354C0`):

| Driver Build | `.rdata` `'RSMB'` RVA | Raw Context (`'BMSR'` + `Action = 1`) |
|---|---|---|
| `Program Files\EasyAntiCheat_EOS.sys` (`2026-11-25`) | `0x303B74` (`raw 0x302574`) | `42 4d 53 52 01 00 00 00 00 00 00 00 00 00 00 00` |
| `eac_dumped.sys` | `0x2D458C` (`raw 0x2D458C`) | `42 4d 53 52 01 00 00 00 00 00 00 00 00 00 00 00` |
| `eacfn.sys` | `0x2C5C8C` (`raw 0x2C5C8C`) | `42 4d 53 52 01 00 00 00 00 00 00 00 00 00 00 00` |
| `Downloads\EasyAntiCheat_EOS.sys` (`2026-11-24`) | `0x2BE27C` (`raw 0x2BCE7C`) | `42 4d 53 52 01 00 00 00 00 00 00 00 00 00 00 00` |

---

## 4. `KUSER_SHARED_DATA` (`0xFFFFF78000000000`) Reads (Exact Instruction Boundaries)

Note: Every `movabs reg, 0xFFFFF78000000xxx` instruction is `10` bytes (`48/49 b8..bf <imm64>`), where the 64-bit immediate starts at `instruction_rva + 2`. All RVAs below are the **exact instruction start RVAs** (`movabs` opcode byte):

| Offset | Field | `Program Files\EasyAntiCheat_EOS.sys` (`2026-11-25`) | `eac_dumped.sys` | `eacfn.sys` | `Downloads\EasyAntiCheat_EOS.sys` (`2026-11-24`) |
|---|---|---|---|---|---|
| `+0x008` | `InterruptTime` | `0xCCCEB` (`0xCCCBE`), `0x1017A3` | `0x4CF6B`, `0x15187B`, `0x17AA7C` | `0x4E032`, `0x13C959`, `0x146022` | `0xCABBB`, `0x147E42`, `0x1F100C` |
| `+0x014` | `SystemTime` | `0xCCA5B`, `0xF794B`, `0x157415`, `0x171B6A` | `0x171FE2`, `0x17A827`, `0x1B286A`, `0x1CD486`, `0x1F2A10` | `0x4DDE3`, `0x9A2E1`, `0xA590D`, `0x1C6C32` | `0x105CF9`, `0x1DC687`, `0x1EB817`, `0x1F937A` |
| `+0x020` | `TimeZoneBias` | `0x1E12EB` | — | — | `0x13143F`, `0x1A0073` |
| `+0x260` | `NtBuildNumber` | `0x542CC`, `0x1D1A48` | `0xF59A`, `0x149AAF`, `0x21EFF0` | `0x8D2FC`, `0x1CB13B` | `0x1360D0`, `0x207E6D` |
| `+0x274` | `KdDebuggerEnabled` | `0xEFC8B` | `0x2091C8` | `0x2100DE` | `0x1B11B9` |
| `+0x2EC` | `Unidentified / Flags` | `0x1D19B7` | `0x21EF4E` | `0x1CB08C` | `0x207DCA` |
| `+0x320` | `TickCount` | `0xAD4E1`, `0xCC95C`, `0x145EC8`, `0x1C0AD5` | `0x342ED`, `0x17A739`, `0x19FEC4` | `0x370A3`, `0x4DCF5`, `0x1EFC7E` | `0xDB729`, `0x151B35`, `0x187003`, `0x1F9289` |

---

## 5. `CPUID` (`0F A2`) Sites

Leaf `EAX` is XOR-decoded (`xor eax, imm32`) or zeroed (`xor eax, eax`), `ECX` zeroed (`xor ecx, ecx`), `RBX` swapped with a scratch register (`xchg rbx, r8/r9/r10/r11/rdi/rbp`), `0f a2` executed, and `RBX` restored:

| Driver Build | `.text` (`Sec[0]`) Sites | Total Executable Section Sites | Representative `.text` RVAs |
|---|---|---|---|
| `Program Files\EasyAntiCheat_EOS.sys` (`2026-11-25`) | `30` | `130` | `0xFD37` (leaf 0), `0x1B1F9`, `0x4609A`, `0x78104`, `0x90439`, `0xC2738`, `0xC9F6C` |
| `eac_dumped.sys` | `27` | `111` | `0x1E5FF`, `0x1F163`, `0x2480E`, `0x25012`, `0x25871`, `0x2644A`, `0x39C9B`, `0x895ED`, `0xB4490`, `0xCA14F`, `0xF1CC8` |
| `eacfn.sys` | `30` | `91` | `0x10739`, `0x12042`, `0x3C8F4`, `0x3FD76` (leaf 0), `0xAEB24`, `0xBAFE9` |
| `Downloads\EasyAntiCheat_EOS.sys` (`2026-11-24`) | `29` | `113` | `0xF954`, `0x3D9F6`, `0xC0057`, `0xF21FB`, `0x112077`, `0x112893`, `0x1130F0`, `0x113CEC`, `0x13FCD0` (leaf 0) |

---

## 6. Volume Serial, MountMgr, TPM, Monitor EDID, & ACPI/PCI (`eacfn.sys` `.bearimp`)
- **ACPI & PCI Bus Queries**: `eacfn.sys` `.bearimp` reveals imports for `ntoskrnl!HalAcpiGetTableEx` (`RVA 0x2935548`), `ntoskrnl!HalGetBusDataByOffset` (`RVA 0x2935550`), `ntoskrnl!IoGetDeviceInterfaces` (`RVA 0x2935658`), `ntoskrnl!IoWMIOpenBlock` (`RVA 0x2935560`), and `ntoskrnl!NtQuerySystemEnvironmentValueEx` (`RVA 0x2935720`). Their callers reside inside `Sec[7]`.
- **TPM / Volume Serial / MountMgr / Monitor EDID**: Plaintext strings (`IoVolumeDeviceToDosName`, `0x6D0008`, `SetupDiEnumDeviceInfo`, `Tbsi_Get_TCG_Log`) have `0` unobfuscated hits in `.text`/`.rdata` (`UNKNOWN` — either VM-obfuscated inside `Sec[7]` or collected in usermode by `EasyAntiCheat_EOS.exe`).
