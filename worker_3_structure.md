# EAC EOS Protocol, Session Binding, TPM Attestation & Lifecycle Analysis (`worker_3_structure`)

## 1. Executive Summary
Static binary and filesystem inspection across `EasyAntiCheat_EOS.exe` (`v1.5.9`, `32-bit`, `1,041,336` bytes, `ImageBase 0x400000`), `EasyAntiCheat_EOS.exe.bak` (`v1.5.3`, `985,896` bytes), `FortniteClient-Win64-Shipping_EAC_EOS.exe` (`5,210,040` bytes, `ImageBase 0x140000000`), `EOSSDK-Win64-Shipping.dll` (`47,839,632` bytes, `ImageBase 0x180000000`), `EasyAntiCheat_EOS.sys` (`46,171,808` bytes live in `C:\Program Files (x86)\EasyAntiCheat_EOS\`), `eac_dumped.sys` (`40,251,392` bytes), `eacfn.sys` (`43,213,824` bytes), and local `%APPDATA%` / `HKLM` state establishes the complete launch, TPM 2.0 EK/quote key provisioning, shared-memory driver bootstrap, IPC synchronization, and telemetry lifecycle.

---

## 2. Session Token & Machine-Identity Derivation
1. **Launcher / Caldera JWT Bootstrap**:
   - `FortniteLauncher.exe` reads `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EasyAntiCheat\Settings.json` (`352` bytes, `SHA-256=f14b14f41880553c...`: `productid="prod-fn"`, `sandboxid="fn"`, `deploymentid="62a9473a2dca46b29ccf17577fcf42d7"`, `executable="FortniteClient-Win64-Shipping.exe"`, `allow_null_client="false"`).
   - Requests Caldera ES256 JWT (`-caldera=eyJhbGciOiJFUzI1Ni... acProvider=EasyAntiCheatEOS`) and spawns `FortniteClient-Win64-Shipping_EAC_EOS.exe` with `-named_pipe=<EpicUserId>\Fortnite -fromfl=eaceos`.
2. **Telemetry `SessionId` Generation & Binding (`EasyAntiCheat_EOS.exe`)**:
   - At `0x0041012c..0x00410194`, if global `SessionId` length (`dword ptr [0x4d20c8]`) is `0`, `EasyAntiCheat_EOS.exe` calls `0x00416be0` (which generates a random UUID formatted with `%08x-%04x-%04x-%04x-%08x%04x`) and stores it in `std::string` at `0x4d20b8`.
   - `0x00413160` appends this `SessionId` (`0x4d20b8`) onto two Epic DataRouter telemetry URLs:
     - `0x004b082c` (xref `0x004131c7`, length `0xB4`): `https://api.epicgames.dev/telemetry/data/datarouter/api/v1/public/data?AppVersion=1.0.0&AppEnvironment=Production&UploadType=sdkevents&AppID=EOSSDK.AntiCheatExt.Service&SessionId=`
     - `0x004b08e0` (xref `0x0041324b`, length `0xA5`): `https://datarouter.ol.epicgames.com/datarouter/api/v1/public/data?AppVersion=1.0.0&AppEnvironment=Production&UploadType=eteventstream&AppID=easyanticheat&SessionId=`
   - `FortniteClient-Win64-Shipping_EAC_EOS.exe` embeds matching launcher telemetry templates:
     - `RVA 0x35d8cd`: `=EOSSDK.AntiCheatExt.Launcher&SessionId=`
     - `RVA 0x35d982`: `easyanticheat&SessionId=`

---

## 3. Local Cache, Certificates, Config, & Registry Layout
### Filesystem State Observed on Disk
- **`%APPDATA%\EasyAntiCheat\prod-fn\62a9473a2dca46b29ccf17577fcf42d7\`**:
  - `easyanticheat_x64.eac` is not persisted as a plaintext file on disk when the game is not running (streamed into `Global\EasyAntiCheat_EOSBin` shared section during launch).
  - Contains `anticheatlauncher.log` and `13` timestamped `anticheatlauncher-backup-*.log` files (`2,611` to `3,103` bytes each) showing bootstrapper `v2.0.0` (`x86-64`) querying `https://modules-cdn.eac-prod.on.epicgames.com/modules/prod-fn/62a9473a2dca46b29ccf17577fcf42d7/win64` (`HTTP 304`, `No update needed`) and exiting launcher phase with `301, 'Easy Anti-Cheat successfully loaded in-game'`.
- **`C:\Program Files (x86)\EasyAntiCheat_EOS\`**:
  - `EasyAntiCheat_EOS.exe` (`1,041,336` bytes, `v1.5.9`, `TimeDateStamp=0x6AA16B40`, PDB `EasyAntiCheat_EOS_Setup.pdb`)
  - `EasyAntiCheat_EOS.exe.bak` (`985,896` bytes, `v1.5.3`, `TimeDateStamp=0x69B94BB9`)
  - `EasyAntiCheat_EOS.sys` (`46,171,808` bytes, modified `2026-11-25 00:19:40`)
- **`C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EasyAntiCheat\`**:
  - `Settings.json` (`352` bytes) and `DefaultSettings.json` (`453` bytes).
  - `Certificates\base.bin` (`62,621` bytes, `SHA-256=04e4d80cbdeef7d2...`, header magic `45 41 43 00 05 00 00 00` = `"EAC\0"` v5 signed integrity catalog).
  - `Certificates\base.cer` (`1,140` bytes, `SHA-256=b67db25da454d789...`, DER X.509 certificate: Issuer `CN=EasyAntiCheat Integrity Intermediate CA`, Subject `CN=prod-fn`, validity `2023-04-17` to `2083-04-17`).
  - `Certificates\runtime.conf` (`1,108` bytes, `SHA-256=23355cbed29a1b5f...`, encrypted runtime configuration blob).

### Registry Keys & Values
- `HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS`:
  - `Type=16`, `Start=3`, `ErrorControl=1`, `ObjectName=LocalSystem`, `WOW64=332`, `ImagePath="C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe"`.
- `HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\Attestation`:
  - `AttestationKey` (`REG_BINARY`, queried at `0x00432b60..0x00432c8e`: must be `>= 12` bytes with magic `dword[0] == 0x1EAC92F3` at `0x00432c69`; persistent TPM handle stored at `dword[2]` = `[ebp-0x1c]`).
  - `QuoteKeyStatus` (`REG_DWORD`, written at `0x00428bf8` inside `0x00428b30`; status codes: `1` = exported & written to `PlatformQuoteKeys\EacQuoteKey`, `2` = no valid `AttestationKey` handle, `3` = `NCryptOpenStorageProvider` failed, `4` = `NCryptImportKey` failed, `5` = `NCryptExportKey` failed/empty, `6` = `RegOpenKeyExW` on `PlatformQuoteKeys` failed, `7` = `RegSetValueExW` on `EacQuoteKey` failed, `8` = in-progress init set at `0x004250d0`).
  - `QuoteKeyStatusCode` (`REG_DWORD`, written at `0x00428c0f` inside `0x00428b30` with the raw `SECURITY_STATUS` / `LSTATUS` error code).
- `HKLM\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys` (`0x004b1608` -> `0x0041f421`, `0x004b1880` -> `0x00425292`):
  - Value `EacQuoteKey` (`REG_BINARY`, deleted/reset during cleanup at `0x0041f476` via `RegDeleteValueW` and written at `0x00425300` via `RegSetValueExW` with `REG_BINARY = 3` containing the exported `OpaqueKeyBlob`).
- `HKLM\SOFTWARE\WOW6432Node\EasyAntiCheat_EOS` (`0x004be13a`):
  - `ProductsInstalled = "prod-fn;"`
  - `ErrRpt_LastInitTime`, `ErrRpt_LastInitInfo1`, `ErrRpt_LastInitInfo2`, `ErrRpt_LastInitProductId = "prod-fn"`, `ErrRpt_LastInitSandboxId = "fn"`, `ErrRpt_LastInitDeploymentId = "62a9473a2dca46b29ccf17577fcf42d7"`, `ErrRpt_LastInitBuildId = 14280`, `ErrRpt_LastUnloadDuration`, `ErrRpt_ServiceState`.

---

## 4. Service <-> Driver Shared Memory, Deobfuscation & Bootstrap (`0x004241e0..0x00425080`)

### Service Context Struct (`esi` in `0x00424350` / `0x004243c0` / `0x004241e0`)
- `+0x00`: `HANDLE hLauncherOrGameProcess` (opened via `OpenProcess(SYNCHRONIZE = 0x100000, FALSE, pid)` at `0x00424379`)
- `+0x04`: `HANDLE hSection_EOSBin` (`CreateFileMappingW` handle for `Global\EasyAntiCheat_EOSBin` at `0x00424412`)
- `+0x08`: `PVOID pView_EOSBin` (`MapViewOfFile` base pointer at `0x00424436`)
- `+0x0C`: `HANDLE hInternalWakeEvent` (anonymous manual-reset `CreateEventW` at `0x00424394`, signaled by `SetEvent` at `0x0042450b`)
- `+0x10`: `HANDLE hEventModule` (`Global\EasyAntiCheat_EOSEventModule`, manual-reset event created at `0x00424490`)
- `+0x14`: `HANDLE hEventDriver` (`Global\EasyAntiCheat_EOSEventDriver`, manual-reset event created at `0x004244a7`)
- `+0x18`: `HANDLE hEventGame` (`Global\EasyAntiCheat_EOSEventGame`, manual-reset event created at `0x004244be`)
- `+0x1C`: `SC_HANDLE hDriverService` (returned by `0x004284d0` at `0x00424fa2`, closed via `CloseServiceHandle` at `0x004242a9`)

### Shared Section `Global\EasyAntiCheat_EOSBin` Layout (`0x004243e4..0x00424485`)
1. **DACL Security Descriptor (`0x004243ec`)**:
   - `ConvertStringSecurityDescriptorToSecurityDescriptorW` (`0x004afdea`) parses SDDL `L"D:(A;OICI;GA;;;BG)(A;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"` (`0x004beede`).
2. **Section Allocation (`0x00424401..0x0042443c`)**:
   - `CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE (4), 0, 0x06000000 (100,663,296 bytes = 96 MB), L"Global\\EasyAntiCheat_EOSBin")`.
   - `MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS (0xF001F), 0, 0, 0x06000000)`.
3. **Header Initialization (`0x00424447..0x00424485`)**:
   - `[pView + 0x00] = 0x00000001` (protocol/header version `1`)
   - `[pView + 0x04] = 0x06000000` (total shared section size `96 MB`)
   - `[pView + 0x08] = 0x00090000` (`589,824` bytes control/metadata offset)
   - `[pView + 0x0C] = 0x00010005` (flags/version)
   - `[pView + 0x10] = 0x00000000` (populated by game/module with target Game PID, read at `0x0042461d` and passed to `OpenProcess(0x101000, ...)` at `0x0042462c`)
   - `[pView + 0x14] = 0x00000000`
   - `[pView + 0x18] = 0x00000000` (`cbDriverImageSize`, validated `< 0x05FFFFE5` at `0x004248a6`)
   - `[pView + 0x1C] = uint8_t DriverImageBlob[cbDriverImageSize]` (payload buffer)

### Driver Image Staging, Rolling Deobfuscation & Service Load (`0x00424520..0x00424fc2`)
1. `0x0042458b`: Waits via `WaitForMultipleObjects(3, &[hInternalWakeEvent, hLauncherProcess, hEventModule], FALSE, INFINITE)` until the bootstrapper signals `Global\EasyAntiCheat_EOSEventModule` (`WAIT_OBJECT_0 + 2`), then calls `0x004246f0`.
2. Inside `0x004246f0`:
   - Stops/cleans any prior `EasyAntiCheat_EOSSys` instance (`0x00424796..0x00424844`, timeout `0x1D4C` = `7500` ms, error string `L"EAC unload timeout"` at `0x004bd1bc`).
   - Checks `cbDriverImageSize = [pView + 0x18]` is non-zero and `< 0x05FFFFE5` (`100,663,269` bytes); otherwise logs `L"Invalid binary size."` (`0x004beb0c`).
   - **In-place Rolling Deobfuscation (`0x0042499a..0x00424a0d`)**: If `cbDriverImageSize > 1`, reverses a rolling byte-cipher over `[pView + 0x1C .. pView + 0x1B + cbDriverImageSize]` (iterating backwards `ecx -= 2` with `dl += 6`, `sub bl, [eax+ecx+0x1d]`, `add bl, dl`, `sub bh, bl`, `add bh, [eax+ecx+0x1b] + 3`).
   - Opens the target `.sys` path via `CreateFileW` (`0x00424a7b` / `0x00424b61` / `0x00424bb7`, retrying after `Sleep(5000)` if `GetLastError() == ERROR_SHARING_VIOLATION (0x20)`), writes the deobfuscated `[pView + 0x1C]` image to disk (`WriteFile`), verifies the Authenticode signature (`0x00423aa0` at `0x00424cb8`, checking `"Epic Games Inc."` / `"Epic Games, Inc."`), and starts the kernel driver service (`0x004284d0` at `0x00424fa2`, which calls `CreateServiceW` / `StartServiceW`).
3. After `0x004246f0` returns `true`, `0x004245dc..0x0042466b` switches the 3rd wait handle to `Global\EasyAntiCheat_EOSEventGame` (`[eax+0x18]`), waits for it to be signaled, reads the game PID from `[pView + 0x10]` (`0x0042461d`), opens the game process with `0x101000` (`SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`), runs `0x004250a0` (`EacQuoteKey` export), and enters `0x004253e0` (which queries `K32GetProcessImageFileNameW` at `0x0042542a` and monitors game process exit).

---

## 5. Complete TPM 2.0 EK Certificate & `EacQuoteKey` Disassembly (`0x0041f3e7..0x0041f558`, `0x00423fd0..0x004240f7`, `0x004250a0..0x0042536f`, `0x00432b60..0x00433cc0`)

### A. TPM 2.0 Device Check & EK Certificate Provisioning (`0x00423fd0..0x004240f7`)
Spawned as a worker thread from `0x00424360` (`push 0x423fd0; call 0x413e20`):
1. `0x00423ffd..0x00424036`: Calls `LoadLibraryW(L"tbs.dll")` and `GetProcAddress(hTbs, "Tbsi_GetDeviceInfo")`.
2. `0x00424050..0x00424066`: Calls `Tbsi_GetDeviceInfo(0x10, &info)` (`sizeof(TBS_DEVICE_INFO) = 16`) and checks `info.tpmVersion == 2` (`cmp dword ptr [ebp-0x60], 2` = `TPM_VERSION_20`).
3. `0x00424068..0x004240d7`: Loads `L"TpmCoreProvisioning.dll"` (`0x004b17b6`), resolves `"TpmRetrieveEkCertificate"` (`0x004b17e6`), invokes `TpmRetrieveEkCertificate()` with 0 arguments (`call ecx` at `0x004240d1`) to ensure the Windows EK certificate cache is provisioned, and frees both libraries.

### B. `AttestationKey` Registry Reader (`0x00432b60..0x00432ca3`)
Called by both `0x0041f48d` and `0x004250de`:
1. Opens `HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\Attestation` (`0x004b1af2`) with `KEY_ALL_ACCESS` (`0xF003F`).
2. Queries value `L"AttestationKey"` (`0x004b1b72`) via `RegQueryValueExW` (`0x00432c2f`) to check `cbData >= 0x0C` (`12` bytes), then reads the 12-byte struct via `RegGetValueW` (`RRF_RT_REG_BINARY = 8` at `0x00432c55`):
   ```c
   struct EacAttestationKeyRegBlob {
       uint32_t Magic;           // +0x00: must equal 0x1EAC92F3 (checked at 0x00432c69)
       uint32_t VersionOrFlags;  // +0x04: checked == 1 at 0x00432c79
       uint32_t TpmKeyHandle;    // +0x08: persistent TPM 2.0 key handle (e.g. 0x8100xxxx), returned in EAX (0x00432c8b)
   };
   ```

### C. NCrypt `PcpTpmPersistentKeyBlob` Import & `OpaqueKeyBlob` Export (`0x004250a0..0x0042536f`)
1. `0x004250d0`: Writes initial state `QuoteKeyStatus = 8`, `QuoteKeyStatusCode = 0` via `0x00428b30`.
2. `0x004250de`: Calls `0x00432b60(NULL)` to read `TpmKeyHandle` from `Attestation\AttestationKey`. If `0` (missing or invalid magic), writes `QuoteKeyStatus = 2` (`0x00425126`), sleeps `30,000` ms (`0x7530` in retry thread `0x004253c0` spawned at `0x00424650`), and retries.
3. `0x0042510b`: Calls `NCryptOpenStorageProvider(&hProvider, L"Microsoft Platform Crypto Provider", 0)` (`0x004afdf0`). On failure, records `QuoteKeyStatus = 3`, `QuoteKeyStatusCode = eax`.
4. `0x0042513c..0x00425178`: Constructs a 12-byte `PCP_TPM12_IDBINDING_BLOB` / `PcpTpmPersistentKeyBlob` header on the stack at `[ebp-0xbc]`:
   ```c
   struct PcpTpmPersistentKeyBlob {
       uint32_t Magic;        // [ebp-0xbc] = 0x4D54504B ('KPTM') at 0x0042513c
       uint32_t cbHeader;     // [ebp-0xb8] = 0x0000000C (12 bytes) at 0x0042514c
       uint32_t TpmKeyHandle; // [ebp-0xb4] = esi (persistent TPM handle from AttestationKey) at 0x00425146
   };
   ```
   and calls `NCryptImportKey(hProvider, 0, L"PcpTpmPersistentKeyBlob", NULL, &hKey, &blob, 0x0C, 0)` (`0x004afdf6`). On failure, records `QuoteKeyStatus = 4`.
5. `0x004251a1..0x00425212`: Queries the size and exports the PCP key blob via two calls to `NCryptExportKey(hKey, 0, L"OpaqueKeyBlob", NULL, pbOutput, cbOutput, &cbResult, 0)` (`0x004afe02`). On failure, records `QuoteKeyStatus = 5`.
6. `0x00425247..0x00425326`: Opens `HKLM\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys` (`0x004b1880`) via `RegOpenKeyExW` (failure -> `QuoteKeyStatus = 6`), writes `L"EacQuoteKey"` (`REG_BINARY = 3`) with the exported `OpaqueKeyBlob` bytes via `RegSetValueExW` (`0x00425300`, failure -> `QuoteKeyStatus = 7`, success -> `QuoteKeyStatus = 1`), and logs the final status to `Services\EasyAntiCheat_EOS\Attestation` (`0x00428b30`).

### D. Direct TPM 2.0 Command Submission via `tbs.dll` (`0x0041f3e7..0x0041f558` & `0x004331d0..0x00433cc0`)
During service teardown/cleanup (`0x0041f3e7..0x0041f558`):
1. `0x0041f465..0x0041f47f`: Opens `HKLM\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys` and deletes `L"EacQuoteKey"` via `RegDeleteValueW`.
2. `0x0041f48d`: Calls `0x00432b60(&shouldEvict)` to check if `Attestation\AttestationKey` (`0x1EAC92F3`) has eviction flag set (`[ebp-0x20] == 1 || [ebp-0x18] != 0`).
3. If true, initializes a statically linked **TSS2 ESYS/TCTI-TBS** context (`0x004331d0` -> `0x00433bb0`, magic `0x761E188A` / `0xFBF2AFA3`):
   - `0x00433c3f`: Calls `Tbsi_Context_Create(&params, &hTbsContext)` (`0x004afe50`) with `TBS_CONTEXT_PARAMS2` (`version = 2` at `[esp+0x10]`, `asUINT32 = 4` = `includeTpm20` at `[esp+0x14]`).
   - `0x00433c52`: Calls `Tbsi_GetDeviceInfo(0x10, &info)` (`0x004afe56`) and verifies `tpmVersion == 2`.
4. `0x0041f50a..0x0041f528`: Calls `0x00433410` -> `0x00433370` -> `0x00433580` with TPM2 command code **`0x00000120` (`TPM2_CC_EvictControl`)** (`push 0x120` at `0x00433389`), tag `0x8002` (`TPM2_ST_SESSIONS`), hierarchy `0x40000001` (`TPM2_RH_OWNER` pushed at `0x0041f522`), session `0x40000009` (`TPM2_RS_PW` at `0x0041f513`), and persistent handle `ebx` (`TpmKeyHandle`), serializing big-endian fields via `bswap` (`0x00433950`) and submitting the raw TPM 2.0 command buffer through `Tbsip_Submit_Command(hTbsContext, TBS_COMMAND_LOCALITY_ZERO (0), TBS_COMMAND_PRIORITY_NORMAL (0xC8 = 200), pbCmd, cbCmd, pbResp, &cbResp)` at `0x00433af2` (`call 0x4afe3e`).

---

## 6. Error Strings & `common.processing` Kick Analysis
1. **`errors.com.epicgames.common.processing`**:
   - Not present in `EasyAntiCheat_EOS.exe`, `FortniteClient-Win64-Shipping_EAC_EOS.exe`, `EOSSDK-Win64-Shipping.dll`, `EasyAntiCheat_EOS.sys`, `eac_dumped.sys`, or `eacfn.sys`.
   - Backend Epic match-rejection code returned when server-side challenge, TPM quote key attestation, or hardware telemetry evaluation rejects the session.
2. **Complete `EasyAntiCheat_EOS.exe` Event Taxonomy (`0x00413440` -> `.rdata 0x004b0a31..0x004b0cfe`)**:
   - `23` distinct event IDs (`0..22`) plus default `AntiCheat.Error.Undefined` (see full table in `worker_2_network.md` Section 4).
3. **`EOSSDK-Win64-Shipping.dll` Auth/Challenge Error Strings**:
   - `RVA 0x1ac9546`: `: Failed to authenticate with the server after challenge.`
   - `RVA 0x1bf28d0`: `EOS_Auth_CorrectiveActionRequired`
   - `RVA 0x1bf3bb8`: `EOS_AntiCheat_ClientProtectionNotAvailable`
   - `RVA 0x1bf3d68`: `EOS_AntiCheat_ProtectMessageValidationFailed`

---

## 7. Full Protocol Lifecycle (Launch -> Post-Match)
1. **Launch**: `FortniteLauncher.exe` reads `Settings.json`, fetches Caldera ES256 JWT, spawns `FortniteClient-Win64-Shipping_EAC_EOS.exe` with `-named_pipe=<EpicUserId>\Fortnite -fromfl=eaceos`.
2. **Shared Memory & Service Start**: `EasyAntiCheat_EOS.exe` (`v1.5.9`) creates 96 MB shared section `Global\EasyAntiCheat_EOSBin` and events `Global\EasyAntiCheat_EOSEvent{Module,Driver,Game}`, spawns `0x00423fd0` to verify `TPM_VERSION_20` via `tbs.dll!Tbsi_GetDeviceInfo` and provision EK cert via `TpmCoreProvisioning.dll!TpmRetrieveEkCertificate`.
3. **Driver Deobfuscation & Load**: Bootstrapper writes obfuscated driver bytes into `Global\EasyAntiCheat_EOSBin` (`+0x1C`, size at `+0x18`) and signals `Global\EasyAntiCheat_EOSEventModule`. `EasyAntiCheat_EOS.exe` (`0x004246f0`) applies the rolling byte cipher (`0x0042499a..0x00424a0d`), writes `EasyAntiCheat_EOS.sys` to disk, verifies the `"Epic Games"` Authenticode chain, and starts `EasyAntiCheat_EOSSys`.
4. **TPM `EacQuoteKey` Export**: Once `Global\EasyAntiCheat_EOSEventGame` signals, `EasyAntiCheat_EOS.exe` reads `Attestation\AttestationKey` (magic `0x1EAC92F3`, spawned by `EasyAntiCheat_EOS.sys`), imports the persistent TPM handle (`'KPTM'` header) via `NCryptImportKey(L"PcpTpmPersistentKeyBlob")`, exports `L"OpaqueKeyBlob"` via `NCryptExportKey`, writes it to `HKLM\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\EacQuoteKey`, and sets `QuoteKeyStatus = 1`.
5. **In-Game Session**: `EOSSDK-Win64-Shipping.dll` calls `EOS_AntiCheatClient_BeginSession` (`RVA 0x00e75010`), exchanges encrypted challenge/`HEARTBEAT` frames with the server via `ReceiveMessageFromServer` (`RVA 0x00e75480`) / `AddNotifyMessageToServer` (`RVA 0x00e74c00`), and raises `AddNotifyClientIntegrityViolated` (`RVA 0x00e74f40`) on violation.
6. **Teardown & Telemetry**: On exit, `EasyAntiCheat_EOS.exe` (`0x0041f3e7`) deletes `PlatformQuoteKeys\EacQuoteKey`, issues `TPM2_CC_EvictControl` (`0x00000120`) via `tbs.dll!Tbsip_Submit_Command` if eviction is requested, and posts `{"Events":[...]}` diagnostics (`S0`..`S7`, `LastBuildId`) to `api.epicgames.dev` and `datarouter.ol.epicgames.com`.
