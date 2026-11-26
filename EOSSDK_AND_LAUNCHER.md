# EOSSDK Anti-Cheat Interface & Launcher Bootstrapper Analysis

Verified directly against on-disk Fortnite Win64 binaries (`2026-11-25`):
- `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EOSSDK-Win64-Shipping.dll` (`47,839,632` bytes, `ImageBase = 0x180000000`, `SizeOfImage = 0x2E92000`, `EntryRVA = 0x1A6D9F0`, `TimeDateStamp = 0x6ADBA68D`)
- `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping_EAC_EOS.exe` (`5,210,040` bytes, `ImageBase = 0x140000000`, `SizeOfImage = 0x502000`, `EntryRVA = 0x2A37C0`, `TimeDateStamp = 0x6AE1DD7A`)
- `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EasyAntiCheat\Settings.json` (`352` bytes)
- `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EasyAntiCheat\Certificates\base.bin` (`62,621` bytes) & `base.cer` (`1,140` bytes)

---

## 1. `EOSSDK-Win64-Shipping.dll` Section Layout & Architecture

| Index | Name | `VirtualAddress` | `VirtualSize` | `RawPtr` | `RawSize` | `Characteristics` |
|---|---|---|---|---|---|---|
| `0` | `.text` | `0x0001000` | `0x1A74901` | `0x0000400` | `0x1A74A00` | `0x60000020` |
| `1` | `malloc_h` | `0x1A76000` | `0x00007D9` | `0x1A74E00` | `0x0000800` | `0x60000020` |
| `2` | `.rodata` | `0x1A77000` | `0x00008C0` | `0x1A75600` | `0x0000A00` | `0x60000020` |
| `3` | `.rdata` | `0x1A78000` | `0x11E9932` | `0x1A76000` | `0x11E9A00` | `0x40000040` |
| `4` | `.data` | `0x2C62000` | `0x011B788` | `0x2C5FA00` | `0x0029600` | `0xC0000040` |
| `5` | `.pdata` | `0x2D7E000` | `0x00EC5EC` | `0x2C89000` | `0x00EC600` | `0x40000040` |
| `6` | `.eos` | `0x2E6B000` | `0x00000A4` | `0x2D75600` | `0x0000200` | `0x40000040` |
| `7` | `_RDATA` | `0x2E6C000` | `0x0002308` | `0x2D75800` | `0x0002400` | `0x40000040` |
| `8` | `.rsrc` | `0x2E6F000` | `0x00068A8` | `0x2D77C00` | `0x0006A00` | `0x40000040` |
| `9` | `.reloc` | `0x2E76000` | `0x001BEC4` | `0x2D7E600` | `0x001C000` | `0x42000040` |

### Vtable Dispatch Convention in `EOS_AntiCheatClient_*`
Every exported `EOS_AntiCheatClient_*` API (`RVA 0x0E74C00..0x0E75740`) validates non-null handle `RCX` (`EOS_HAntiCheatClient`) and required option pointers (`RDX`, `R8`, `R9`), dereferences the internal implementation object `rcx = *(void**)rcx`, loads its vtable `rax = *(void***)rcx`, and tail-calls through a fixed vtable offset (`call qword ptr [rax + offset]`). When any required pointer is `NULL`, the wrapper checks the global log verbosity byte at `0x182D1093E` (`cmp byte ptr [rip + disp32], 2`), logs a diagnostic if enabled, and returns `0xA` (`EOS_InvalidParameters`) or `0` (`EOS_INVALID_NOTIFICATIONID` for `AddNotify*`).

---

## 2. Complete `EOS_AntiCheatClient_*` Export & Vtable Table (`27` Exports)

| Ordinal | Export RVA | Function Name | Vtable Offset / Null Return |
|---|---|---|---|
| `30` | `0x0E74C00` | `EOS_AntiCheatClient_AddNotifyMessageToServer` | `call [rax + 0x00]` (null -> `0`) |
| `47` | `0x0E74C70` | `EOS_AntiCheatClient_RemoveNotifyMessageToServer` | `call [rax + 0x08]` |
| `29` | `0x0E74CD0` | `EOS_AntiCheatClient_AddNotifyMessageToPeer` | `call [rax + 0x10]` (null -> `0`) |
| `46` | `0x0E74D40` | `EOS_AntiCheatClient_RemoveNotifyMessageToPeer` | `call [rax + 0x18]` |
| `31` | `0x0E74DA0` | `EOS_AntiCheatClient_AddNotifyPeerActionRequired` | `call [rax + 0x20]` (null -> `0`) |
| `48` | `0x0E74E10` | `EOS_AntiCheatClient_RemoveNotifyPeerActionRequired` | `call [rax + 0x28]` |
| `32` | `0x0E74E70` | `EOS_AntiCheatClient_AddNotifyPeerAuthStatusChanged` | `call [rax + 0x30]` (null -> `0`) |
| `49` | `0x0E74EE0` | `EOS_AntiCheatClient_RemoveNotifyPeerAuthStatusChanged` | `call [rax + 0x38]` |
| `28` | `0x0E74F40` | `EOS_AntiCheatClient_AddNotifyClientIntegrityViolated` | `call [rax + 0x40]` (null -> `0`) |
| `45` | `0x0E74FB0` | `EOS_AntiCheatClient_RemoveNotifyClientIntegrityViolated` | `call [rax + 0x48]` |
| `33` | `0x0E75010` | `EOS_AntiCheatClient_BeginSession` | `call [rax + 0x50]` (null -> `0xA`) |
| `34` | `0x0E75080` | `EOS_AntiCheatClient_EndSession` | `call [rax + 0x58]` (null -> `0xA`) |
| `40` | `0x0E750F0` | `EOS_AntiCheatClient_PollStatus` | `call [rax + 0x60]` (null -> `0xA`) |
| `38` | `0x0E75160` | `EOS_AntiCheatClient_GetSystemConfig` | `call [rax + 0x68]` |
| `50` | `0x0E751D0` | `EOS_AntiCheatClient_Reserved02` | `call [rax + 0x70]` |
| `35` | `0x0E75240` | `EOS_AntiCheatClient_GetModuleBuildId` | `call [rax + 0x78]` |
| `39` | `0x0E752B0` | `EOS_AntiCheatClient_GetSystemRequirementStatus` | `call [rax + 0x80]` |
| `36` | `0x0E75330` | `EOS_AntiCheatClient_GetPersistentSetting` | `call [rax + 0x88]` |
| `51` | `0x0E753A0` | `EOS_AntiCheatClient_SetPersistentSetting` | `call [rax + 0x90]` |
| `27` | `0x0E75410` | `EOS_AntiCheatClient_AddExternalIntegrityCatalog` | `call [rax + 0x98]` (null -> `0xA`) |
| `43` | `0x0E75480` | `EOS_AntiCheatClient_ReceiveMessageFromServer` | `call [rax + 0xA0]` (null -> `0xA`) |
| `37` | `0x0E754F0` | `EOS_AntiCheatClient_GetProtectMessageOutputLength` | `call [rax + 0xA8]` |
| `41` | `0x0E75560` | `EOS_AntiCheatClient_ProtectMessage` | `call [rax + 0xB0]` (null -> `0xA`) |
| `52` | `0x0E755E0` | `EOS_AntiCheatClient_UnprotectMessage` | `call [rax + 0xB8]` (null -> `0xA`) |
| `44` | `0x0E75660` | `EOS_AntiCheatClient_RegisterPeer` | `call [rax + 0xC0]` |
| `53` | `0x0E756D0` | `EOS_AntiCheatClient_UnregisterPeer` | `call [rax + 0xC8]` |
| `42` | `0x0E75740` | `EOS_AntiCheatClient_ReceiveMessageFromPeer` | `call [rax + 0xD0]` |

### Disassembly of Core Server-Tunneling Entry Points
```asm
; EOS_AntiCheatClient_BeginSession @ RVA 0x0E75010
0x0e75010: sub  rsp, 0x28
0x0e75014: test rcx, rcx
0x0e75017: je   0xe7502c
0x0e75019: test rdx, rdx
0x0e7501c: je   0xe7502c
0x0e7501e: mov  rcx, qword ptr [rcx]
0x0e75021: mov  rax, qword ptr [rcx]
0x0e75024: call qword ptr [rax + 0x50]
0x0e75027: add  rsp, 0x28
0x0e7502b: ret

; EOS_AntiCheatClient_ReceiveMessageFromServer @ RVA 0x0E75480
0x0e75480: sub  rsp, 0x28
0x0e75484: test rcx, rcx
0x0e75487: je   0xe7549f
0x0e75489: test rdx, rdx
0x0e7548c: je   0xe7549f
0x0e7548e: mov  rcx, qword ptr [rcx]
0x0e75491: mov  rax, qword ptr [rcx]
0x0e75494: call qword ptr [rax + 0xa0]
0x0e7549a: add  rsp, 0x28
0x0e7549e: ret
```

---

## 3. Complete `EOS_AntiCheatServer_*` Export Table (`28` Exports)

| Ordinal | Export RVA | Function Name |
|---|---|---|
| `56` | `0x0E757B0` | `EOS_AntiCheatServer_AddNotifyMessageToClient` |
| `76` | `0x0E75820` | `EOS_AntiCheatServer_RemoveNotifyMessageToClient` |
| `54` | `0x0E75880` | `EOS_AntiCheatServer_AddNotifyClientActionRequired` |
| `74` | `0x0E758F0` | `EOS_AntiCheatServer_RemoveNotifyClientActionRequired` |
| `55` | `0x0E75950` | `EOS_AntiCheatServer_AddNotifyClientAuthStatusChanged` |
| `75` | `0x0E759C0` | `EOS_AntiCheatServer_RemoveNotifyClientAuthStatusChanged` |
| `57` | `0x0E75A20` | `EOS_AntiCheatServer_BeginSession` |
| `58` | `0x0E75A90` | `EOS_AntiCheatServer_EndSession` |
| `72` | `0x0E75B00` | `EOS_AntiCheatServer_RegisterClient` |
| `81` | `0x0E75B70` | `EOS_AntiCheatServer_UnregisterClient` |
| `71` | `0x0E75BE0` | `EOS_AntiCheatServer_ReceiveMessageFromClient` |
| `77` | `0x0E75C50` | `EOS_AntiCheatServer_SetClientDetails` |
| `79` | `0x0E75CC0` | `EOS_AntiCheatServer_SetGameSessionId` |
| `78` | `0x0E75D30` | `EOS_AntiCheatServer_SetClientNetworkState` |
| `59` | `0x0E75DA0` | `EOS_AntiCheatServer_GetProtectMessageOutputLength` |
| `70` | `0x0E75E10` | `EOS_AntiCheatServer_ProtectMessage` |
| `80` | `0x0E75E80` | `EOS_AntiCheatServer_UnprotectMessage` |
| `73` | `0x0E75F00` | `EOS_AntiCheatServer_RegisterEvent` |
| `60` | `0x0E75F70` | `EOS_AntiCheatServer_LogEvent` |
| `62` | `0x0E75FE0` | `EOS_AntiCheatServer_LogGameRoundStart` |
| `61` | `0x0E76050` | `EOS_AntiCheatServer_LogGameRoundEnd` |
| `65` | `0x0E760C0` | `EOS_AntiCheatServer_LogPlayerSpawn` |
| `63` | `0x0E76130` | `EOS_AntiCheatServer_LogPlayerDespawn` |
| `64` | `0x0E761A0` | `EOS_AntiCheatServer_LogPlayerRevive` |
| `67` | `0x0E76210` | `EOS_AntiCheatServer_LogPlayerTick` |
| `69` | `0x0E76280` | `EOS_AntiCheatServer_LogPlayerUseWeapon` |
| `68` | `0x0E762F0` | `EOS_AntiCheatServer_LogPlayerUseAbility` |
| `66` | `0x0E76360` | `EOS_AntiCheatServer_LogPlayerTakeDamage` |

---

## 4. Bootstrapper (`FortniteClient-Win64-Shipping_EAC_EOS.exe`, `v2.0.0`)

### Section Layout (`ImageBase = 0x140000000`, `EntryRVA = 0x2A37C0`)
- `Sec[0]` `.text`: `RVA 0x001000..0x2E4D96` (`RawSize = 0x2E3E00`)
- `Sec[1]` `.rdata`: `RVA 0x2E5000..0x49CEF4` (`RawSize = 0x1B8000`)
- `Sec[2]` `.data`: `RVA 0x49D000..0x4AEBD8` (`RawSize = 0x009C00`)
- `Sec[3]` `.pdata`: `RVA 0x4AF000..0x4D5124` (`12,955` `RUNTIME_FUNCTION` entries)
- `Sec[4]` `.fptable`, `Sec[5]` `.tls`, `Sec[6]` `_RDATA`, `Sec[7]` `.rsrc`, `Sec[8]` `.reloc`

### Static Import Profile (`14` DLLs, `419` Imported Functions)
- `KERNEL32.dll` (`177`), `USER32.dll` (`112`), `WS2_32.dll` (`25`), `GDI32.dll` (`23`), `WINMM.dll` (`21`), `CRYPT32.dll` (`16`), `ADVAPI32.dll` (`13`), `IMM32.dll` (`9`), `SHELL32.dll` (`7`), `SETUPAPI.dll` (`6`), `ole32.dll` (`5`), `VERSION.dll` (`3`), `OLEAUT32.dll` (`1`), `bcrypt.dll` (`1`: `BCryptGenRandom`).

### CDN Module Provisioning & Local `Settings.json`
- Queries CDN endpoints embedded at `RVA 0x414BBC` and `RVA 0x414C1F`:
  - `https://modules-cdn.eac-prod.on.epicgames.com/modules/{{product_id}}/{{deployment_id}}/{{system}}`
  - `https://modules-cdn.eac-gamedev.on.epicgames.com/modules/{{product_id}}/{{deployment_id}}/{{system}}`
- Substitutes values from `EasyAntiCheat\Settings.json` (`RVA 0x415162`):
  - `productid`: `"prod-fn"`
  - `sandboxid`: `"fn"`
  - `deploymentid`: `"62a9473a2dca46b29ccf17577fcf42d7"`
  - `executable`: `"FortniteClient-Win64-Shipping.exe"`
  - `allow_null_client`: `"false"`
- Stages the encrypted kernel module payload into `Global\EasyAntiCheat_EOSBin` (`96 MB` section created by `EasyAntiCheat_EOS.exe`), signals `Global\EasyAntiCheat_EOSEventModule`, waits for `Global\EasyAntiCheat_EOSEventDriver`, launches `FortniteClient-Win64-Shipping.exe` forwarding `-caldera=... -named_pipe=<EpicUserId>\Fortnite -fromfl=eaceos`, writes the game PID to `[pView + 0x10]`, and signals `Global\EasyAntiCheat_EOSEventGame`.
