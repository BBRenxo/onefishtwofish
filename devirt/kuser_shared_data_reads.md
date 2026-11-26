# Devirtualization: `KUSER_SHARED_DATA` (`0xFFFFF78000000000`) Offset Reads

## Ground-Truth DDK Audit (`_KUSER_SHARED_DATA` in `ntddk.h` + x64 Disassembly)
1. **`+0x274` is `BOOLEAN ProcessorFeatures[64]` (`+0x274..+0x2B3`)**, NOT `KdDebuggerEnabled` (`KdDebuggerEnabled` resides at `+0x2D4`, which has `0` direct `movabs` sites). At `RVA 0xEFC8B` (`eos_live`), `0x2091C8` (`eac_dumped`), `0x2100DE` (`eacfn`), and `0x1B11B9` (`eos_44m`), the instruction loads `0xFFFFF78000000274` as a pointer argument (`RCX`/`R8`/`R9`) into an affine-decrypted buffer-hash/copy helper (`call r10`) to snapshot the 64-byte CPU feature array.
2. **`+0x2EC` is `BOOLEAN SafeBootMode`**, NOT `ConsoleSessionForegroundProcessId`. Across all four builds (`0x1D19B7` `eos_live`, `0x21EF4E` `eac_dumped`, `0x1CB08C` `eacfn`, `0x207DCA` `eos_44m`), the function is an identical 13-byte leaf helper: `movabs rax, 0xFFFFF780000002EC; mov al, byte ptr [rax]; ret`.

## Cross-Build RVA Matrix (Exact `movabs` Instruction Boundaries)
| Offset | Verified `_KUSER_SHARED_DATA` Field | `eac_dumped.sys` RVAs | `eacfn.sys` RVAs | `EasyAntiCheat_EOS.sys` (`44.4 MB`) RVAs | `EasyAntiCheat_EOS.sys` (`46.17 MB` live) RVAs |
|---|---|---|---|---|---|
| `+0x008` | `InterruptTime` (`KSYSTEM_TIME`) | `0x4CF6B`, `0x15187B`, `0x17AA7C`, `0xE5AF85` (`Sec[7]`), `0x19B87DB` (`Sec[7]`) | `0x4E032`, `0x13C959`, `0x146022`, `0x1F71D8D` (`Sec[7]`), `0x2141F52` (`Sec[7]`) | `0xCABBB`, `0x147E42`, `0x1F100C`, `0x16C53C4` (`Sec[7]`) | `0xCCCBE`, `0x1017A3`, `0x1426D7E` (`Sec[7]`), `0x184EC74` (`Sec[7]`), `0x1B4B3AE` (`Sec[7]`) |
| `+0x014` | `SystemTime` (`KSYSTEM_TIME`) | `0x171FE2`, `0x17A827`, `0x1B286A`, `0x1CD486`, `0x1F2A10`, `0x12DB663` (`Sec[7]`), `0x151B4C7` (`Sec[7]`), `0x186E71D` (`Sec[7]`), `0x21D5096` (`Sec[7]`) | `0x4DDE3`, `0x9A2E1`, `0xA590D`, `0x1C6C32`, `0x126C56E` (`Sec[7]`), `0x1317748` (`Sec[7]`), `0x1AA87DE` (`Sec[7]`), `0x216822E` (`Sec[7]`) | `0x105CF9`, `0x1DC687`, `0x1EB817`, `0x1F937A`, `0x17E776A` (`Sec[7]`), `0x17F8753` (`Sec[7]`) | `0xCCA5B`, `0xF794B`, `0x157415`, `0x171B6A`, `0x133126F` (`Sec[7]`), `0x15A9D1A` (`Sec[7]`), `0x1EE86F8` (`Sec[7]`), `0x1F85742` (`Sec[7]`) |
| `+0x020` | `TimeZoneBias` (`KSYSTEM_TIME`) | `0x1C95B8A` (`Sec[7]`), `0x25ADDE3` (`Sec[7]`) | `0x15E8E6C` (`Sec[7]`), `0x1FBF7CB` (`Sec[7]`) | `0x13143F`, `0x1A0073` | `0x1E12EB`, `0x1ADA0B1` (`Sec[7]`) |
| `+0x260` | `NtBuildNumber` (`ULONG`) | `0x0F59A`, `0x149AAF`, `0x21EFF0`, `0x18717D8` (`Sec[7]`), `0x1871824` (`Sec[7]`) | `0x8D2FC`, `0x1CB13B`, `0x1B02C4E` (`Sec[7]`), `0x2364242` (`Sec[7]`), `0x23642BB` (`Sec[7]`) | `0x1360D0`, `0x207E6D`, `0x187B391` (`Sec[7]`) | `0x542CC`, `0x1D1A48`, `0x18D420D` (`Sec[7]`), `0x234DDD5` (`Sec[7]`) |
| `+0x274` | `ProcessorFeatures[64]` (`BOOLEAN[64]`) | `0x2091C8` | `0x2100DE` | `0x1B11B9` | `0xEFC8B` |
| `+0x2EC` | `SafeBootMode` (`BOOLEAN`) | `0x21EF4E` | `0x1CB08C` | `0x207DCA` | `0x1D19B7` |
| `+0x320` | `TickCount` (`KSYSTEM_TIME`) | `0x342ED`, `0x17A739`, `0x19FEC4`, `0xF1EA30` (`Sec[7]`) | `0x370A3`, `0x4DCF5`, `0x1EFC7E`, `0x1BD9DC8` (`Sec[7]`) | `0xDB729`, `0x151B35`, `0x187003`, `0x1F9289` | `0xAD4E1`, `0xCC95C`, `0x145EC8`, `0x1C0AD5` |

- **Handlers / Instructions Stepped**: `79` (`arith=18`, `mem=31`, `branch=9`, `exit=1`)

## Inputs Read (`KUSER_SHARED_DATA` Page `0xFFFFF78000000000`)

## Pseudo-C Reconstruction
```c
void eac_sample_kuser_shared_data(eac_kuser_snapshot_t* out) {
    out->interrupt_time = *(volatile uint64_t*)0xFFFFF78000000008ULL;
    out->system_time    = *(volatile uint64_t*)0xFFFFF78000000014ULL;
    out->timezone_bias  = *(volatile uint64_t*)0xFFFFF78000000020ULL;
    out->tick_count     = *(volatile uint64_t*)0xFFFFF78000000320ULL;
    out->nt_build_number = *(volatile uint32_t*)0xFFFFF78000000260ULL;
    eac_copy_or_hash_features(out->processor_features, (const uint8_t*)0xFFFFF78000000274ULL, 64);
    out->safe_boot_mode  = *(volatile uint8_t*)0xFFFFF780000002ECULL;
}
```

## Executed Instructions (Unicorn Traces)
### eac_dumped.sys +0x014 SystemTime (RVA 0x0171fe2)
```asm
RVA 0x0171fe2: 48bf1400000080f7ffff     movabs rdi, 0xfffff78000000014
RVA 0x0171fec: 490f45fe                 cmovne rdi, r14
RVA 0x0171ff0: 4c0f4417                 cmove r10, qword ptr [rdi]
```

### eac_dumped.sys +0x260 NtBuildNumber (RVA 0x000f59a)
```asm
RVA 0x000f59a: 48b86002000080f7ffff     movabs rax, 0xfffff78000000260
RVA 0x000f5a4: 8b00                     mov eax, dword ptr [rax]
RVA 0x000f5a6: 3b4524                   cmp eax, dword ptr [rbp + 0x24]
RVA 0x000f5a9: 8b4d20                   mov ecx, dword ptr [rbp + 0x20]
RVA 0x000f5ac: 7703                     ja 0xf5b1
RVA 0x000f5ae: 8b4d1c                   mov ecx, dword ptr [rbp + 0x1c]
RVA 0x000f5b1: 4c8b4d08                 mov r9, qword ptr [rbp + 8]
RVA 0x000f5b5: 4931f1                   xor r9, rsi
RVA 0x000f5b8: 48b8ffffffffffffff0f     movabs rax, 0xfffffffffffffff
RVA 0x000f5c2: 4c21c0                   and rax, r8
RVA 0x000f5c5: 49c1e83c                 shr r8, 0x3c
RVA 0x000f5c9: 4c8b5dd8                 mov r11, qword ptr [rbp - 0x28]
RVA 0x000f5cd: 4889542428               mov qword ptr [rsp + 0x28], rdx
RVA 0x000f5d2: 4889442420               mov qword ptr [rsp + 0x20], rax
RVA 0x000f5d7: 4c89d2                   mov rdx, r10
RVA 0x000f5da: 41ffd3                   call r11
```

### eac_dumped.sys +0x274 ProcessorFeatures[0] (RVA 0x02091c8)
```asm
RVA 0x02091c8: 49b87402000080f7ffff     movabs r8, 0xfffff78000000274
RVA 0x02091d2: 4989d9                   mov r9, rbx
```

### eac_dumped.sys +0x2EC SafeBootMode (RVA 0x021ef4e)
```asm
RVA 0x021ef4e: 48b8ec02000080f7ffff     movabs rax, 0xfffff780000002ec
RVA 0x021ef58: 8a00                     mov al, byte ptr [rax]
RVA 0x021ef5a: c3                       ret 
```

### eac_dumped.sys +0x320 TickCount (RVA 0x00342ed)
```asm
RVA 0x00342ed: 48b82003000080f7ffff     movabs rax, 0xfffff78000000320
RVA 0x00342f7: 4c8b28                   mov r13, qword ptr [rax]
RVA 0x00342fa: 48b8483ea7ddbaa89b4a     movabs rax, 0x4a9ba8badda73e48
RVA 0x0034304: 480fafc3                 imul rax, rbx
RVA 0x0034308: 488b0da1112d00           mov rcx, qword ptr [rip + 0x2d11a1]
RVA 0x003430f: 48f7d8                   neg rax
RVA 0x0034312: 4c8b0401                 mov r8, qword ptr [rcx + rax]
RVA 0x0034316: 48b81bd1170032f5e385     movabs rax, 0x85e3f5320017d11b
RVA 0x0034320: 480fafc3                 imul rax, rbx
RVA 0x0034324: 488b0d8d112d00           mov rcx, qword ptr [rip + 0x2d118d]
RVA 0x003432b: 48f7d8                   neg rax
RVA 0x003432e: 488b1401                 mov rdx, qword ptr [rcx + rax]
RVA 0x0034332: 488b053fc02c00           mov rax, qword ptr [rip + 0x2cc03f]
RVA 0x0034339: 4c29f8                   sub rax, r15
RVA 0x003433c: 4889f9                   mov rcx, rdi
RVA 0x003433f: ffd0                     call rax
```

### EasyAntiCheat_EOS.sys (live 46.17MB) +0x014 SystemTime (RVA 0x00cca5b)
```asm
RVA 0x00cca5b: 48b81400000080f7ffff     movabs rax, 0xfffff78000000014
RVA 0x00cca65: 488b00                   mov rax, qword ptr [rax]
RVA 0x00cca68: 4829c8                   sub rax, rcx
RVA 0x00cca6b: 764d                     jbe 0xccaba
RVA 0x00ccaba: 31c0                     xor eax, eax
RVA 0x00ccabc: c3                       ret 
```

### EasyAntiCheat_EOS.sys (live 46.17MB) +0x260 NtBuildNumber (RVA 0x00542cc)
```asm
RVA 0x00542cc: 48b96002000080f7ffff     movabs rcx, 0xfffff78000000260
RVA 0x00542d6: 8b09                     mov ecx, dword ptr [rcx]
RVA 0x00542d8: 3b4d24                   cmp ecx, dword ptr [rbp + 0x24]
RVA 0x00542db: 448b4d20                 mov r9d, dword ptr [rbp + 0x20]
RVA 0x00542df: 7704                     ja 0x542e5
RVA 0x00542e1: 448b4d1c                 mov r9d, dword ptr [rbp + 0x1c]
RVA 0x00542e5: 488b4d08                 mov rcx, qword ptr [rbp + 8]
RVA 0x00542e9: 4831f1                   xor rcx, rsi
RVA 0x00542ec: 4c8b5dd8                 mov r11, qword ptr [rbp - 0x28]
RVA 0x00542f0: 4c89542420               mov qword ptr [rsp + 0x20], r10
RVA 0x00542f5: 4c89c2                   mov rdx, r8
RVA 0x00542f8: 4989c0                   mov r8, rax
RVA 0x00542fb: 41ffd3                   call r11
```

### EasyAntiCheat_EOS.sys (live 46.17MB) +0x274 ProcessorFeatures[0] (RVA 0x00efc8b)
```asm
RVA 0x00efc8b: 48b97402000080f7ffff     movabs rcx, 0xfffff78000000274
RVA 0x00efc95: 4989d8                   mov r8, rbx
```

### EasyAntiCheat_EOS.sys (live 46.17MB) +0x2EC SafeBootMode (RVA 0x01d19b7)
```asm
RVA 0x01d19b7: 48b8ec02000080f7ffff     movabs rax, 0xfffff780000002ec
RVA 0x01d19c1: 8a00                     mov al, byte ptr [rax]
RVA 0x01d19c3: c3                       ret 
```

### EasyAntiCheat_EOS.sys (live 46.17MB) +0x320 TickCount (RVA 0x00ad4e1)
```asm
RVA 0x00ad4e1: 48b82003000080f7ffff     movabs rax, 0xfffff78000000320
RVA 0x00ad4eb: 488b00                   mov rax, qword ptr [rax]
RVA 0x00ad4ee: 4889442428               mov qword ptr [rsp + 0x28], rax
RVA 0x00ad4f3: 48b8c2dc86aab48e236f     movabs rax, 0x6f238eb4aa86dcc2
RVA 0x00ad4fd: 490fafc4                 imul rax, r12
RVA 0x00ad501: 488b0df8c62600           mov rcx, qword ptr [rip + 0x26c6f8]
RVA 0x00ad508: 48f7d8                   neg rax
RVA 0x00ad50b: 488b0c01                 mov rcx, qword ptr [rcx + rax]
RVA 0x00ad50f: 48b826f20dffefacd789     movabs rax, 0x89d7acefff0df226
RVA 0x00ad519: 490fafc4                 imul rax, r12
RVA 0x00ad51d: 488b15e4c62600           mov rdx, qword ptr [rip + 0x26c6e4]
RVA 0x00ad524: 48f7d8                   neg rax
RVA 0x00ad527: 488b1402                 mov rdx, qword ptr [rdx + rax]
RVA 0x00ad52b: 4989c9                   mov r9, rcx
RVA 0x00ad52e: 4921f1                   and r9, rsi
```
