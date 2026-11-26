# EAC Network & HTTPS Stack Analysis (`worker_2_network`)

Targets analyzed:
- `C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe` (`ProductVersion=1.5.9`, `x86` / `Machine=0x14c`, `ImageBase=0x400000`, `SizeOfImage=0x103000`, `EntryPoint RVA=0x83840`, `TimeDateStamp=0x6AA16B40`, `1,041,336` bytes, `SHA-256=0bbe6d48f45fc155...`)
- `C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe.bak` (`ProductVersion=1.5.3`, `x86` / `Machine=0x14c`, `ImageBase=0x400000`, `SizeOfImage=0xF3000`, `EntryPoint RVA=0x74200`, `TimeDateStamp=0x69B94BB9`, `985,896` bytes, `SHA-256=b8f03456397d455a...`)
- `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping_EAC_EOS.exe` (`x86_64`, `ImageBase=0x140000000`, `SizeOfImage=0x502000`, `EntryPoint RVA=0x2A37C0`, `TimeDateStamp=0x6AE1DD7A`, `5,210,040` bytes)
- `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EOSSDK-Win64-Shipping.dll` (`x86_64`, `ImageBase=0x180000000`, `SizeOfImage=0x2E92000`, `EntryPoint RVA=0x1A6D9F0`, `TimeDateStamp=0x6ADBA68D`, `47,839,632` bytes)

---

## 1. PE Imports & Transport Architecture (`EasyAntiCheat_EOS.exe` v1.5.9)

`EasyAntiCheat_EOS.exe` does not statically import `wininet.dll`, `winhttp.dll`, `libssl`/`libcrypto` (OpenSSL/BoringSSL), or `mbedtls`. It statically links **libcurl** configured with the **Windows Schannel (`schannel`)** TLS backend over `WS2_32.dll` and `CRYPT32.dll`, plus `tbs.dll` and `ncrypt.dll` via indirect jump thunks (`0x004afdf0..0x004afe56`).

| Imported DLL | Count | Key Functions & IAT Slots (`ImageBase = 0x400000`) |
|---|---|---|
| `WS2_32.dll` | 25 | `WSAStartup` (`0x4cc274`), `WSACleanup` (`0x4cc264`), `getaddrinfo` (`0x4cc290`), `freeaddrinfo` (`0x4cc28c`), `socket` (`0x4cc2c4`), `connect` (`0x4cc288`), `send` (`0x4cc2bc`), `recv` (`0x4cc2b4`), `select` (`0x4cc2b8`), `ioctlsocket` (`0x4cc2a8`), `setsockopt` (`0x4cc2c0`), `getsockopt` (`0x4cc29c`), `closesocket` (`0x4cc284`), `WSAIoctl` (`0x4cc26c`), `WSAGetLastError` (`0x4cc268`), `__WSAFDIsSet` (`0x4cc278`, thunk `0x4afe38`) |
| `CRYPT32.dll` | 15 | `CertOpenStore` (`0x4cc2f8`), `CertCreateCertificateChainEngine` (`0x4cc2d4`), `CertGetCertificateChain` (`0x4cc2f0`), `CertFreeCertificateChain` (`0x4cc2e4`), `CertFreeCertificateChainEngine` (`0x4cc2e8`), `CertGetNameStringW` (`0x4cc2f4`), `CertFindExtension` (`0x4cc2e0`), `CryptDecodeObjectEx` (`0x4cc2fc`), `CryptQueryObject` (`0x4cc300`), `CryptStringToBinaryW` (`0x4cc304`), `CertFindCertificateInStore` (`0x4cc2dc`), `CertEnumCertificatesInStore` (`0x4cc2d8`), `CertAddCertificateContextToStore` (`0x4cc2cc`), `CertFreeCertificateContext` (`0x4cc2ec`), `CertCloseStore` (`0x4cc2d0`) |
| `ncrypt.dll` | 4 | `NCryptOpenStorageProvider` (`0x4cc244`, thunk `0x4afdf0`), `NCryptImportKey` (`0x4cc240`, thunk `0x4afdf6`), `NCryptFreeObject` (`0x4cc23c`, thunk `0x4afdfc`), `NCryptExportKey` (`0x4cc238`, thunk `0x4afe02`) |
| `tbs.dll` | 5 | `Tbsi_Context_Create` (`0x4cc30c`, thunk `0x4afe50`), `Tbsi_GetDeviceInfo` (`0x4cc310`, thunk `0x4afe56`), `Tbsip_Cancel_Commands` (`0x4cc314`, thunk `0x4afe4a`), `Tbsip_Context_Close` (`0x4cc318`, thunk `0x4afe44`), `Tbsip_Submit_Command` (`0x4cc31c`, thunk `0x4afe3e`) |
| `ADVAPI32.dll` | 39 | `CryptAcquireContextW` (`0x4cc1b4`), `CryptCreateHash` (`0x4cc1b8`), `CryptHashData` (`0x4cc1c8`), `CryptGetHashParam` (`0x4cc1c4`), `CryptGenRandom` (`0x4cc1c0`), `CryptDestroyHash` (`0x4cc1bc`), `CryptReleaseContext` (`0x4cc1cc`), `RegCreateKeyExW` (`0x4cc1fc`), `RegOpenKeyExW` (`0x4cc20c`), `RegSetValueExW` (`0x4cc214`), `RegQueryValueExW` (`0x4cc210`), `RegGetValueW` (`0x4cc208`), `RegDeleteValueW` (`0x4cc204`), `ConvertStringSecurityDescriptorToSecurityDescriptorW` (`0x4cc1a8`, thunk `0x4afdea`) |
| `KERNEL32.dll` | 149 | `CreateFileMappingW` (`0x4cbf44`), `MapViewOfFile` (`0x4cc0c4`), `UnmapViewOfFile` (`0x4cc154`), `CreateEventW` (`0x4cbf40`), `SetEvent` (`0x4cc110`), `WaitForMultipleObjects` (`0x4cc164`), `CreateFileW` (`0x4cbf48`), `OpenProcess` (`0x4cc0d8`), `K32GetProcessImageFileNameW` (`0x4cc0a0`, thunk `0x4afe08`) |

Dynamic library resolutions in `EasyAntiCheat_EOS.exe`:
- `winhttp.dll` (`0x4bbe08`): `WinHttpOpen` (`0x4bbdc9`), `WinHttpGetIEProxyConfigForCurrentUser` (`0x4bbd05`), and `WinHttpGetProxyForUrl` (`0x4bbdf2`) resolved at `VA 0x4029fa` (`RVA 0x29fa`) for proxy auto-detection.
- `TpmCoreProvisioning.dll` (`0x4b17b6`): `TpmRetrieveEkCertificate` (`0x4b17e6`) resolved via `LoadLibraryW` (`0x42408a`) + `GetProcAddress` (`0x4240ae`) inside `0x423fd0`.
- `Wevtapi.dll`: `EvtQuery`, `EvtRender`, `EvtCreateRenderContext`, `EvtClose` resolved dynamically for Windows Event Log crash/bugcheck inspection.
- `wintrust.dll`: `WTHelperProvDataFromStateData`, `WTHelperGetProvSignerFromChain`, `WTHelperGetProvCertFromChain` resolved dynamically for Authenticode chain validation.

---

## 2. Socket & DNS Call Sites (`WS2_32.dll`)

| API | Call Site RVA | Call Site VA | Raw Instruction Bytes | Enclosing Func RVA (VA) | Callers |
|---|---|---|---|---|---|
| `WS2_32.dll!connect` | `0x4986a` | `0x44986a` | `ff 15 88 c2 4c 00` (`call dword ptr [0x4cc288]`) | `0x495b0` (`0x4495b0`) | `0x448b64` (`0x48a80`) <- `0x442d56` (`0x42c80`); `0x449f86` (`0x49ef0`) <- `0x4487c8`/`0x4488da`/`0x448929` (`0x485a0`) |
| `WS2_32.dll!connect` | `0x5a5d6` | `0x45a5d6` | `ff 15 88 c2 4c 00` | `0x5a4e0` (`0x45a4e0`) | `0x43941a` (`0x39360`) <- `0x434d27`; `0x43e06a` (`0x3e000`) <- `0x43dea8` |
| `WS2_32.dll!getaddrinfo` | `0x611b2` | `0x4611b2` | `ff 15 90 c2 4c 00` (`call dword ptr [0x4cc290]`) | `0x61190` (`0x461190`) | `0x43e12b` (`0x3e0f0`) |
| `WS2_32.dll!send` | `0x3e1a5` | `0x43e1a5` | `ff 15 bc c2 4c 00` (`call dword ptr [0x4cc2bc]`) | `0x3e0f0` (`0x43e0f0`) | `0x43e0f0` (async resolver/socket helper) |
| `WS2_32.dll!send` | `0x47f30` | `0x447f30` | `ff 15 bc c2 4c 00` | `0x47ef0` (`0x447ef0`) | `0x4480c1` (`0x480a0`) <- `0x45f203` (`0x5eea0`), `0x45f633`/`0x45f704`/`0x45f9d8` (`0x5f450`, Schannel send) |
| `WS2_32.dll!send` | `0x5a628` | `0x45a628` | `ff 15 bc c2 4c 00` | `0x5a4e0` (`0x45a4e0`) | `0x43941a`, `0x43e06a` |
| `WS2_32.dll!recv` | `0x47dbe` | `0x447dbe` | `ff 15 b4 c2 4c 00` (`call dword ptr [0x4cc2b4]`) | `0x47db0` (`0x447db0`) | `0x45edd3` (`0x5ed80`), `0x45f296` (`0x5eea0`), `0x45f6ad`/`0x45fa55`/`0x45febc` (`0x5f450`, Schannel recv) |
| `WS2_32.dll!recv` | `0x48229` | `0x448229` | `ff 15 b4 c2 4c 00` | `0x48170` (`0x448170`) | `0x447f21` (`0x47ef0`) |

---

## 3. TLS Stack Initialization & Certificate Verification (`libcurl` + `Schannel`)

Embedded TLS backend strings confirm statically linked **libcurl** with **Schannel**:
- `CURL_SSL_BACKEND` (`RVA=0xc3408`, `VA=0x4c3408`)
- `schannel` / `Schannel` (`RVA=0xc1268`, `VA=0x4c1268`)
- `Microsoft Unified Security Protocol Provider` (`UTF-16LE` Schannel SSP provider)
- `schannel: AcquireCredentialsHandle failed: %s` (`RVA=0xc03bc`, `VA=0x4c03bc`)
- `schannel: initial InitializeSecurityContext failed: %s` (`RVA=0xc02c0`, `VA=0x4c02c0`)
- `schannel: next InitializeSecurityContext failed: %s` (`RVA=0xc028c`, `VA=0x4c028c`)
- `schannel: TLS 1.3 is not yet supported` (`RVA=0xc2220`, `VA=0x4c2220`)
- `schannel: CertGetCertificateChain failed: %s` (`RVA=0xc033c`, `VA=0x4c033c`)
- `schannel: server certificate name verification failed` (`RVA=0xc23b8`, `VA=0x4c23b8`)

### libcurl Option Configuration (`curl_easy_setopt` at `0x434dd0`)
In `0x4012a0..0x4020b0` (wrapped by HTTP client class `0x40e1f0..0x40e920` and invoked by `0x412d30`):
- `0x4012e2` (`RVA=0x12e2`): `CURLOPT_NOSIGNAL` (`0x63` = `99`, value `1`)
- `0x401347` (`RVA=0x1347`): `CURLOPT_PROTOCOLS` (`0xb5` = `181`, value `3` = `CURLPROTO_HTTP | CURLPROTO_HTTPS`)
- `0x401388` (`RVA=0x1388`): `CURLOPT_ERRORBUFFER` (`0x272d` = `10029`)
- `0x4013ca` (`RVA=0x13ca`): `CURLOPT_HEADERFUNCTION` (`0x4e6f` = `20079`, callback `0x401500`)
- `0x401e80` (`RVA=0x1e80`): `CURLOPT_HTTPHEADER` (`0x2727` = `10023`)
- `0x401f7c` (`RVA=0x1f7c`): `CURLOPT_POST` (`0x2f` = `47`, value `1`)
- `0x402048` (`RVA=0x2048`): `CURLOPT_POSTFIELDSIZE` (`0x3c` = `60`)
- Timeout settings in `0x412f8e..0x412fb3`: pushes `0x9c4` (`2500` ms) to `0x40e900` (`CURLOPT_CONNECTTIMEOUT_MS`) and `0x40e920` (`CURLOPT_TIMEOUT_MS`), connects to port `0x1bb` (`443`) at `0x412fe1`, and checks HTTP status `200..299` (`add eax, -200; cmp eax, 100; setb al` at `0x412fff..0x413007`).

Secondary DoH (`%s?dns=%s`, `0x4bfff4`) client at `0x47d920..0x47dab8`:
- Sets `CURLOPT_URL` (`0x2712`), `CURLOPT_WRITEFUNCTION` (`0x4e2b`, `0x47d7c0`), `CURLOPT_WRITEDATA` (`0x2711`), `CURLOPT_COPYPOSTFIELDS` (`0x271f`), `CURLOPT_POSTFIELDSIZE` (`0x3c`), `CURLOPT_HTTPHEADER` (`0x2727`), `CURLOPT_PROTOCOLS` (`0xb5`, value `2` = `CURLPROTO_HTTPS`).

### Certificate Pinning Status
- `libcurl`'s generic `Curl_pin_peer_pubkey` (`0x462780`, `RVA=0x62780`) and `sha256//` parser (`0x441c00`, `RVA=0x41c00`) exist in `.text` (with error string `"SSL: public key does not match pinned public key!"` at `0x4c4f54` / `0x4bf3d4`).
- `CURLOPT_PINNEDPUBLICKEY` (`10230` = `0x27f6`) has `0` references anywhere in `EasyAntiCheat_EOS.exe` `.text`.
- Certificate validation uses `CRYPT32!CertGetCertificateChain` (`0x480750` inside `0x4804d0`, called by `0x4639c0` -> `0x465010`) and `CRYPT32!CertGetNameStringW` (`0x480db8`) against the Windows root CA store and SNI hostname.

---

## 4. Complete Disassembly of Datarouter HTTPS Endpoints & JSON Event Serializer (`0x4101c0..0x413802`, `0x425570..0x4277fd`)

### Observed Endpoints in `EasyAntiCheat_EOS.exe` (`0x413160`)
`0x413160` (`std::string* __cdecl BuildDatarouterUrl(std::string* out_url, int endpoint_type)`) selects between two base URLs and appends the global `SessionId` string at `0x4d20b8` (length at `0x4d20c8`, capacity at `0x4d20cc`, initialized at `0x410135` via `0x416be0` GUID formatter `%08x-%04x-%04x-%04x-%08x%04x`):
1. **Production SDK Events Datarouter (`endpoint_type == 0`)**:
   - URL (`RVA=0xb082c`, `VA=0x4b082c`, length `0xB4` = `180` bytes pushed at `0x4131c2`):
     `https://api.epicgames.dev/telemetry/data/datarouter/api/v1/public/data?AppVersion=1.0.0&AppEnvironment=Production&UploadType=sdkevents&AppID=EOSSDK.AntiCheatExt.Service&SessionId=`
   - Invoked from `0x4129ab` (`push eax; push 0; call 0x412d30`).
2. **ET EventStream Datarouter (`endpoint_type == 1`)**:
   - URL (`RVA=0xb08e0`, `VA=0x4b08e0`, length `0xA5` = `165` bytes pushed at `0x413246`):
     `https://datarouter.ol.epicgames.com/datarouter/api/v1/public/data?AppVersion=1.0.0&AppEnvironment=Production&UploadType=eteventstream&AppID=easyanticheat&SessionId=`
   - Invoked from `0x412aa8` (`push eax; push 1; call 0x412d30`).

### Exact JSON Payload Structure & Serializer (`0x4101c0`)
Function `0x4101c0` (`std::string* __cdecl SerializeDatarouterPayload(std::string* out_json, EventVector* events)`) serializes a vector of `0x24`-byte event objects (`stride = 0x24` at `0x4102a3`, count computed via `imul eax, 0x38e38e39` at `0x412038`). Each event object has:
- `+0x00..+0x17`: `std::string EventName` (mapped from event ID `0..22` by `0x413440`)
- `+0x18..+0x23`: `std::vector<EventField>` (`begin` at `+0x18`, `end` at `+0x1c`, `capacity` at `+0x20`), where each `EventField` is `0x34` (`52`) bytes (`stride = 0x34` at `0x411baf`, count computed via `imul eax, 0xc4ec4ec5` at `0x411e86`):
  - `+0x00..+0x17`: `std::string Key` (escaped via `0x407210` at `0x411bee`)
  - `+0x18..+0x2F`: `std::string Value` (escaped via `0x407210` at `0x411d41`)
  - `+0x30`: `uint32_t IsRawNumeric` (`0` = string value wrapped in `"..."` using `":"` at `0x4bc3ce` and closing `"` at `0x411e71`; non-zero = unquoted integer/boolean using `":` at `0x4bc0a1`, checked via `cmp dword ptr [ecx+0x30], 0` at `0x411ca9` and `0x411d96`).

Exact field serialization order inside `0x4101c0`:
1. `0x410238..0x410260`: Writes outer prefix `{"Events":[` (constructed as stack immediate `7b 22 45 76` `65 6e 74 73` `22 3a 5b 00`).
2. `0x4102e4..0x41039a`: Writes `{"EventName":"<EventName>",` (`7b 22 45 76` `65 6e 74 4e` `61 6d 65 22` `22 3a 22 00` + `event->EventName` + `",` from `0x4bc339`).
3. `0x4105a6..0x410680`: Writes `"Source":"Service/1.5.9",` (stack immediate `53 65 72 76` `69 63 65 2f` `31 2e 35 2e` `39 00` at `0x4105a6..0x4105ba` + `"Source":"` at `0x4105d9..0x4105ed`).
4. `0x41086d..0x410930`: Calls `0x416cf0` to format `"Sep  9 2026 14:20:37"` and writes `"BuildTime":"<BuildTime>",` (`22 42 75 69` `6c 64 54 69` `6d 65 22 3a` `22 00`).
5. `0x410b1c..0x410c40`: Reads global `ProductId` (`std::string` at `0x4d2070`, len `0x4d2080`, cap `0x4d2084`) and writes `"ProductId":"<ProductId>",`.
6. `0x410dec..0x410f10`: Reads global `SandboxId` (`std::string` at `0x4d2088`, len `0x4d2098`, cap `0x4d209c`) and writes `"SandboxId":"<SandboxId>",`.
7. `0x4110bc..0x4111d0`: Loads `""DeploymentId":""` from `0x4b07f8`, reads global `DeploymentId` (`std::string` at `0x4d20a0`, len `0x4d20b0`, cap `0x4d20b4`), and writes `"DeploymentId":"<DeploymentId>",`.
8. `0x411376..0x411450`: Writes `"OSName":"Windows",` (stack immediate `57 69 6e 64` `6f 77 73 00` at `0x411376..0x41137d`).
9. `0x41162d..0x4116e0`: Calls `0x412740` (formats OS version via `%u.%u %s (Build %u.%u)`) and writes `"OSVer":"<OSVer>",`.
10. `0x4118c0..0x4119e0`: Formats integer `BuildId` and writes `"BuildId":<BuildId>,` (followed by `,` from `0x4bc33a`).
11. `0x411b6f..0x411fc7`: Iterates over `event->Fields` (`0x34`-byte entries) and writes `"<Key>":"<Value>"` (or `"<Key>":<Value>` when `+0x30 != 0`), separated by `,` (`0x4bc33a`).
12. `0x411fd0..0x412155`: Closes each event with `}` (`0x4bbb77`), separates multiple events with `,` (`0x41206e`), and closes the envelope with `]}` (`0x7d5d` at `0x41213f`).

### Event ID -> `EventName` Mapping Table (`0x413440..0x4137f7`)
Function `0x413440` maps `uint32_t event_id` (`0x00..0x16`) to its Datarouter `EventName` string:

| `event_id` | Branch VA | String VA | `EventName` |
|---|---|---|---|
| `0` (`0x00`) | `0x4136df` | `0x4b0a31` | `AntiCheat.Generic.TestValue` |
| `1` (`0x01`) | `0x41362b` | `0x4b0a4d` | `AntiCheat.Error.Bugcheck` |
| `2` (`0x02`) | `0x413659` | `0x4b0a66` | `AntiCheat.Error.BugcheckDetailed` |
| `3` (`0x03`) | `0x413642` | `0x4b0a87` | `AntiCheat.Error.GameTrust` |
| `4` (`0x04`) | `0x413553` | `0x4b0aa1` | `AntiCheat.Error.GameApplicationError` |
| `5` (`0x05`) | `0x41378d` | `0x4b0ac6` | `AntiCheat.Error.IntegrityViolation` |
| `6` (`0x06`) | `0x41375a` | `0x4b0ae9` | `AntiCheat.Warning.ChunkFailure` |
| `7` (`0x07`) | `0x4134d0` | `0x4b0b08` | `AntiCheat.Warning.GameTerminationAbnormal` |
| `8` (`0x08`) | `0x4137ac` | `0x4b0b32` | `AntiCheat.Error.GameHardError` |
| `9` (`0x09`) | `0x41376e` | `0x4b0b50` | `AntiCheat.Warning.AbnormalShutdown` |
| `10` (`0x0A`) | `0x413601` | `0x4b0b73` | `AntiCheat.Error.Launch` |
| `11` (`0x0B`) | `0x4136f6` | `0x4b0b8a` | `AntiCheat.Warning.BadOSVersion` |
| `12` (`0x0C`) | `0x413678` | `0x4b0ba9` | `AntiCheat.Error.ValidateError` |
| `13` (`0x0D`) | `0x41348c` | `0x4b0bc7` | `AntiCheat.Info.DriverInitResult` |
| `14` (`0x0E`) | `0x413724` | `0x4b0be7` | `AntiCheat.Error.ServiceUpdateFailed` |
| `15` (`0x0F`) | `0x4136a6` | `0x4b0c0b` | `AntiCheat.Info.DriverInitTime` |
| `16` (`0x10`) | `0x413592` | `0x4b0c29` | `AntiCheat.Info.DriverUnloadDuration` |
| `17` (`0x11`) | `0x41370d` | `0x4b0c4d` | `AntiCheat.Error.GameException` |
| `18` (`0x12`) | `0x41368f` | `0x4b0c6b` | `AntiCheat.Error.NetworkProtocol` |
| `19` (`0x13`) | `0x413516` | `0x4b0c8b` | `AntiCheat.Error.Theia` |
| `20` (`0x14`) | `0x413746` | `0x4b0ca1` | `AntiCheat.Info.SandboxInfo` |
| `21` (`0x15`) | `0x4136bd` | `0x4b0cbc` | `AntiCheat.Info.SandboxEventInfoFile` |
| `22` (`0x16`) | `0x4135cf` | `0x4b0ce0` | `AntiCheat.Info.SandboxProcess` |
| `>22` (default) | `0x4137c0` | `0x4b0cfe` | `AntiCheat.Error.Undefined` |

### Custom Event Body Key-Value Construction (`0x425570..0x4277fd`)
In `0x425570` (the service crash/violation/telemetry collector), `11` custom `0x34`-byte `EventField` records are constructed with anonymized positional keys `"D1"`, `"D2"`, `"N1"`, `"N2"`, `"N3"`, `"S1"`..`"S7"`, and `"LastBuildId"`:
- `0x425809`: Key `"D1"` (`0x4bc26e`), string value from `[esi+0x4a0]`.
- `0x425970`: Key `"D2"` (`0x4bc234`), string value from `[esi+0x4b8]`.
- `0x425ae0`: Key `"N1"` (`0x4bc265`), numeric value from `[eax+0x08]` formatted via `0x428150`.
- `0x425b40`: Key `"N2"` (`0x4bc22b`), string/numeric value from `[esi+0x4f8]`.
- `0x425ca0`: Key `"N3"` (`0x4bc1f5`), string/numeric value from `[esi+0x54c]`.
- `0x425e10`: Key `"S1"` (`0x4bc262`), string value from `[eax+0x0c]`.
- `0x425f80`: Key `"S2"` (`0x4bc228`), 64-bit hex value `[esi+0x4e0..0x4e4]` formatted via `"0x%llX"` (`0x4bbf32` at `0x425fcc`).
- `0x426150`: Key `"S3"` (`0x4bc1f2`), 32-bit hex value `[esi+0x4e8]` formatted via `"0x%X"` (`0x4bbf40` at `0x426192`).
- `0x4262e8`: Key `"S4"` (`0x4bc1b8`), string value from `[esi+0x440]`.
- `0x4264f0`: Key `"S5"` (`0x4bc182`), 32-bit hex value `[eax+0x30]` formatted via `"0x%X"` (`0x4bbf40` at `0x426532`).
- `0x4266a9..0x42671c`: Key `"LastBuildId"` (stack immediate `4c 61 73 74` `42 75 69 6c` `64 49 64 00`), integer value from `[esi+0x540]` (`ErrRpt_LastInitBuildId`).
- `0x426e33`: Key `"S6"` (`0x4bc14f`), optional string value from `[esi+0xe0]` (populated by `0x40a2a0`).
- `0x42710a`: Key `"S7"` (`0x4bc10a`), optional string value from `[esi+0xf8]`.
- At `0x427782`, the populated event vector `[esi+0x70]` is dispatched to `0x4128b0` (`push eax; push 2; call 0x4128b0`), which calls `0x4101c0` (`0x4128e6`) and posts the JSON payload to both `api.epicgames.dev` (`0x4129ab`) and `datarouter.ol.epicgames.com` (`0x412aa8`).

---

## 5. Build Diff: `EasyAntiCheat_EOS.exe` (`v1.5.9`) vs `EasyAntiCheat_EOS.exe.bak` (`v1.5.3`)

| Property | `EasyAntiCheat_EOS.exe` (`v1.5.9` - Current) | `EasyAntiCheat_EOS.exe.bak` (`v1.5.3` - Backup) |
|---|---|---|
| File Size | `1,041,336` bytes | `985,896` bytes (`+55,440` bytes in `1.5.9`) |
| `TimeDateStamp` / Build String | `0x6AA16B40` (`"Sep  9 2026 14:20:37"`) | `0x69B94BB9` (`"Mar 17 2026 12:40:14"`) |
| `SizeOfImage` / `EntryPoint` | `0x103000` / `RVA 0x83840` | `0xF3000` / `RVA 0x74200` |
| Sections | `.text`, `.rdata`, `.data`, `.fptable`, **`.tls`**, `.rsrc`, `.reloc` (`7` sections) | `.text`, `.rdata`, `.data`, `.fptable`, `.rsrc`, `.reloc` (`6` sections) |
| Static Imports | Identical `9` DLLs (`245` total imported functions) | Identical `9` DLLs (`245` total imported functions) |
| String Storage & Unpacking | Plaintext `.rdata` strings for Datarouter URLs, `AntiCheat.*` events, `EacQuoteKey`, `AttestationKey`, `TpmCoreProvisioning.dll`, `Wevtapi.dll`, `wintrust.dll`; adds `.tls` section (`VA 0x4d7000`, index `0x4d4f8c`). | Obfuscated/packed `.rdata` string table (16-byte interleaved blocks); lacks `AttestationKey`, `QuoteKeyStatus`, `QuoteKeyStatusCode`, `ErrRpt_LastUnloadDuration`, and `wintrust.dll` helpers. |

---

## 6. Kernel Driver & EOSSDK Transport Summary

- `EasyAntiCheat_EOS.sys` and `eac_dumped.sys` contain **zero** Epic/EAC HTTPS endpoint strings (`api.epicgames.dev`, `datarouter.ol.epicgames.com`, `easyanticheat.net`).
- `EOSSDK-Win64-Shipping.dll` (`ImageBase 0x180000000`) exports `27` `EOS_AntiCheatClient_*` functions (`RVA 0x00e74c00..0x00e75740`) and `28` `EOS_AntiCheatServer_*` functions (`RVA 0x00e757b0..0x00e76360`), plus `EOS_Platform_GetAntiCheatClientInterface` (`RVA 0x00e8fc40`).
- **HWID telemetry and challenge/response frames** are not sent by `EasyAntiCheat_EOS.exe` over Datarouter HTTPS. `EasyAntiCheat_EOS.sys` collects hardware telemetry in Ring-0 and exchanges encrypted frames with the game client and `EOSSDK-Win64-Shipping.dll` (`EOS_AntiCheatClient_AddNotifyMessageToServer` `RVA 0x00e74c00` / `EOS_AntiCheatClient_ReceiveMessageFromServer` `RVA 0x00e75480`), which transports them over the authenticated game-server session.
