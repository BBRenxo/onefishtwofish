# EAC EOS Static & Emulated Binary Analysis Suite

Native C++20 static verification CLI (`eac_inspector.exe`) and Capstone + Unicorn x86_64 trace suite (`devirt/devirt_runner.py`) for cross-build analysis of EasyAntiCheat EOS kernel drivers (`EasyAntiCheat_EOS.sys`, `eac_dumped.sys`, `eacfn.sys`), usermode service (`EasyAntiCheat_EOS.exe` `v1.5.9` and `v1.5.3`), bootstrapper (`FortniteClient-Win64-Shipping_EAC_EOS.exe`), and `EOSSDK-Win64-Shipping.dll`.

## Repository Layout

- `CMakeLists.txt`: CMake C++20 build configuration (`-Wall -Wextra -O2`, static MinGW-w64 runtime link).
- `include/pe_image.hpp`, `src/pe_image.cpp`: Bounds-checked PE32/PE32+ loader, standalone FIPS 180-4 SHA-256 implementation, `.pdata` unwind parser, standard & `.bearimp` import parser, and export directory parser.
- `include/sig_scanner.hpp`, `src/sig_scanner.cpp`: IDA wildcard byte-pattern scanner, `.text` / `Sec[7]` `cpuid` enumerator, `KUSER_SHARED_DATA` `movabs` instruction scanner with verified DDK field mappings (`+0x274 ProcessorFeatures[0]`, `+0x2EC SafeBootMode`), `'RSMB'` / `0x2D1400` / `SMART` detector, `.text` affine pointer call-thunk extractor, and `34` cross-build RVA assertions.
- `include/protocol_decoders.hpp`, `src/protocol_decoders.cpp`: Exact x86 translation and algebraic inverse of the `Global\EasyAntiCheat_EOSBin` rolling byte cipher (`VA 0x0042499a..0x00424a0d`) with 11-size round-trip self-test, MurmurHash3-style prologue `K_state` mixer, `"EAC\0"` v5 `base.bin` catalog parser, and `EOSSDK` export analyzer.
- `src/main.cpp`: CLI entrypoint generating `VERIFICATION_REPORT.md` and `verified_rvas.json`.
- `devirt/devirt_runner.py`: Unicorn x86_64 + Capstone emulation runner generating 6 trace reports under `devirt/`.
- Documentation & Reports:
  - `SUMMARY.md`: Master architectural summary, SHA-256 inventory, and top-10 fingerprinted identifiers.
  - `RVAS_FOR_EMU.md`: Cross-build RVA lookup tables for emulation and static tooling.
  - `VERIFICATION_REPORT.md` & `verified_rvas.json`: Machine-generated C++20 ground-truth verification output.
  - `EOSSDK_AND_LAUNCHER.md`: Complete `27` Client + `28` Server `EOSSDK` export/vtable tables and `v2.0.0` launcher analysis.
  - `worker_1_hwid.md`, `worker_2_network.md`, `worker_3_structure.md`: Subsystem disassembly reports (kernel HWID, service HTTPS/Datarouter, shared-memory bootstrap & TPM 2.0 `EacQuoteKey`).
  - `devirt/driver_entry_and_init.md`, `devirt/affine_import_solver.md`, `devirt/ioctl_storage_query_property.md`, `devirt/smart_rcv_drive_data.md`, `devirt/rsmb_smbios_read.md`, `devirt/kuser_shared_data_reads.md`: Instruction-level Unicorn x86_64 emulation traces.

## Build & Verification Commands

### 1. Build & Run C++20 `eac_inspector.exe` (Windows / MinGW-w64 GCC + Ninja)

```powershell
$env:PATH = 'C:\msys64\ucrt64\bin;C:\Program Files\CMake\bin;' + $env:PATH
cmake -S C:\Users\Administrator\Desktop\eac_reversal -B C:\Users\Administrator\Desktop\eac_reversal\build -G Ninja -DCMAKE_CXX_COMPILER=C:/msys64/ucrt64/bin/g++.exe -DCMAKE_BUILD_TYPE=Release
cmake --build C:\Users\Administrator\Desktop\eac_reversal\build
C:\Users\Administrator\Desktop\eac_reversal\build\eac_inspector.exe --generate-report
```

Expected exit code: `0` (`34/34` kernel RVA checks passed, `11/11` rolling cipher sizes passed, `base.bin` v5 valid, `27` Client / `28` Server `EOSSDK` exports verified).

### 2. Run Unicorn x86_64 Emulation Suite (`devirt_runner.py`)

```powershell
& 'C:\Users\Administrator\.unsloth\studio\unsloth_studio\Scripts\python.exe' 'C:\Users\Administrator\Desktop\eac_reversal\devirt\devirt_runner.py'
```

Expected exit code: `0` (`6` markdown trace reports and `devirt\progress.log` updated).
