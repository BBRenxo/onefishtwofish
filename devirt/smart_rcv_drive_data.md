# Devirtualization: `SMART_RCV_DRIVE_DATA` (`0x7C088`) & `0x7C084` MBA Handlers

## Cross-Build Targets & Entry Points
| Build | Section | Handler Entry RVA | Core MBA RVA | Outgoing Dispatch RVA | Constants Observed |
|---|---|---|---|---|---|
| `EasyAntiCheat_EOS.sys` (`44,398,752` B) | `Sec[7]` | `0x8A292E` | `0x8A3B13..0x8A3FA1` | `0x3E1632` / `0x408562` | `+0x7C0`, `0xFFFFFF`, `0x4573C3`, `0xBA93FD` |
| `eacfn.sys` (`43,213,824` B) | `Sec[7]` | `0x1CD7A15` | `0x1CD7A24..0x1CD7A7D` | `0x3CB732` | `lea rcx, [rax + 0x7C084]`, `-0x40EEE` |

- **Handlers / Instructions Stepped**: `220` (`arith=147`, `mem=59`, `branch=0`, `exit=1`)

## Notes & Static Context
- Note on `.text` false positives: byte-pattern hits for `84 C0 07 00` inside `.text` (`0x7B073` in `eos_44m`, `0xF77EF` in `eos_live`) are `test al, al; je +0x7C0` (`84 C0 0F 84 C0 07 00 00`) instruction boundary overlaps, NOT `SMART_SEND_DRIVE_COMMAND` immediates. Genuine SMART constants reside in `Sec[7]` MBA blocks (`0x8A3B36` in `eos_44m` and `0x1CD7A24` in `eacfn.sys`).
- At `RVA 0x8A3B1B..0x8A3B43` (`eos_44m`), linear-XOR MBA `r8d = (rax + rbp) - 2*(rbp & 0x4573C3)` followed by `lea r9d, [r8 + 0x7C0]; and r9d, 0xFFFFFF` synthesizes `0x0007C088` (`SMART_RCV_DRIVE_DATA`) when `r8d == 0x7B8C8`.

## Inputs Read (Stack & `r12` Virtual Frame)
- `RVA 0x08a2936` read `8` bytes (`0x140000000`) from `0x00007ff802010000`
- `RVA 0x08a293a` read `8` bytes (`0x7ff80202c000`) from `0x00007ff802010190`
- `RVA 0x08a2a21` read `8` bytes (`0x140000000`) from `0x00007ff8020100b8`
- `RVA 0x08a2a41` read `8` bytes (`0x0`) from `0x00007ff802010020`
- `RVA 0x08a3b13` read `8` bytes (`0x7b8c8`) from `0x00007ff801020080`
- `RVA 0x08a3b44` read `8` bytes (`0x0`) from `0x00007ff801020028`
- `RVA 0x08a3b54` read `8` bytes (`0x0`) from `0x00007ff8010200c0`
- `RVA 0x08a3b5c` read `8` bytes (`0x0`) from `0x00007ff801020008`
- `RVA 0x08a3b72` read `4` bytes (`0x0`) from `0x00007ff801020090`
- `RVA 0x08a3bd5` read `8` bytes (`0x0`) from `0x00007ff801020018`
- `RVA 0x08a3bda` read `4` bytes (`0x0`) from `0x00007ff801020130`
- `RVA 0x08a3be1` read `8` bytes (`0x0`) from `0x00007ff8010200f8`
- `RVA 0x08a3c01` read `8` bytes (`0x0`) from `0x00007ff801020008`
- `RVA 0x08a3c14` read `4` bytes (`0x0`) from `0x00007ff801020094`
- `RVA 0x08a3c1f` read `8` bytes (`0x0`) from `0x00007ff801020028`
- `RVA 0x08a3c55` read `8` bytes (`0x0`) from `0x00007ff8010200c0`
- `RVA 0x08a3c79` read `8` bytes (`0x0`) from `0x00007ff8010200b8`
- `RVA 0x08a3cc1` read `4` bytes (`0x1`) from `0x00007ff801020018`
- `RVA 0x08a3ccd` read `4` bytes (`0x1`) from `0x00007ff801020020`
- `RVA 0x08a3cef` read `8` bytes (`0x7b8c8`) from `0x00007ff801020080`
- `RVA 0x08a3cf7` read `8` bytes (`0x0`) from `0x00007ff8010200a0`
- `RVA 0x08a3d02` read `8` bytes (`0x0`) from `0x00007ff801020110`
- `RVA 0x08a3d0e` read `4` bytes (`0x0`) from `0x00007ff801020118`
- `RVA 0x08a3d16` read `4` bytes (`0x0`) from `0x00007ff801020120`
- `RVA 0x08a3d1e` read `8` bytes (`0x0`) from `0x00007ff801020048`
- `RVA 0x08a3d31` read `8` bytes (`0x0`) from `0x00007ff801020098`
- `RVA 0x08a3d62` read `8` bytes (`0x0`) from `0x00007ff8010200a8`
- `RVA 0x08a3d6a` read `4` bytes (`0x0`) from `0x00007ff8010200b0`
- `RVA 0x08a3d72` read `8` bytes (`0x0`) from `0x00007ff801020148`
- `RVA 0x08a3d7a` read `8` bytes (`0xa2ee5a74c3c64916`) from `0x00007ff801020008`
- `RVA 0x1cd7a39` read `8` bytes (`0x0`) from `0x00007ff8010201f0`
- `RVA 0x1cd7a60` read `8` bytes (`0x0`) from `0x00007ff801020110`
- `RVA 0x1cd7a7c` read `8` bytes (`0x0`) from `0x00007ff801020200`

## Outputs Written (Stack & `r12` Virtual Frame)
- `RVA 0x08a292e` wrote `8` bytes (`0x7ff801020200`) to `0x00007ff80101fff8`
- `RVA 0x08a2963` wrote `8` bytes (`0x0`) to `0x00007ff80101fea8`
- `RVA 0x08a298e` wrote `8` bytes (`0x140`) to `0x00007ff80101ff60`
- `RVA 0x08a29cb` wrote `8` bytes (`0x0`) to `0x00007ff80101ffd0`
- `RVA 0x08a2a0c` wrote `8` bytes (`0x7ff80202c000`) to `0x00007ff80101feb0`
- `RVA 0x08a2a29` wrote `8` bytes (`0xcf0392a12d35b238`) to `0x00007ff80101fec8`
- `RVA 0x08a2a49` wrote `8` bytes (`0x0`) to `0x00007ff80101fed0`
- `RVA 0x08a3b4f` wrote `8` bytes (`0x0`) to `0x00007ff801020028`
- `RVA 0x08a3bb1` wrote `8` bytes (`0x1`) to `0x00007ff801020020`
- `RVA 0x08a3bf6` wrote `4` bytes (`0x1`) to `0x00007ff801020018`
- `RVA 0x08a3c8f` wrote `8` bytes (`0xa2ee5a74c3c64916`) to `0x00007ff801020008`
- `RVA 0x1cd7a15` wrote `8` bytes (`0x7ff802028000`) to `0x00007ff802010190`

## Executed Instructions (Unicorn Traces)
### 1. `EasyAntiCheat_EOS.sys` (`Sec[7]` Handler Entry `RVA 0x8A292E..0x8A29E4`)
```asm
RVA 0x08a292e: 55                       push rbp
RVA 0x08a292f: 4881ec58010000           sub rsp, 0x158
RVA 0x08a2936: 498b2c24                 mov rbp, qword ptr [r12]
RVA 0x08a293a: 4d8bbc2490010000         mov r15, qword ptr [r12 + 0x190]
RVA 0x08a2942: 48b9431bf7d2408fd934     movabs rcx, 0x34d98f40d2f71b43
RVA 0x08a294c: 31f6                     xor esi, esi
RVA 0x08a294e: 4939cf                   cmp r15, rcx
RVA 0x08a2951: 400f97c6                 seta sil
RVA 0x08a2955: 488d942450010000         lea rdx, [rsp + 0x150]
RVA 0x08a295d: 4889f1                   mov rcx, rsi
RVA 0x08a2960: 4989f6                   mov r14, rsi
RVA 0x08a2963: 4889742408               mov qword ptr [rsp + 8], rsi
RVA 0x08a2968: 480fafca                 imul rcx, rdx
RVA 0x08a296c: 89ef                     mov edi, ebp
RVA 0x08a296e: 81e7ffffff00             and edi, 0xffffff
RVA 0x08a2974: 448d8dc0070000           lea r9d, [rbp + 0x7c0]
RVA 0x08a297b: 4181e1ffffff00           and r9d, 0xffffff
RVA 0x08a2982: 4889ee                   mov rsi, rbp
RVA 0x08a2985: 48c1ee18                 shr rsi, 0x18
RVA 0x08a2989: 89f3                     mov ebx, esi
RVA 0x08a298b: 4989f2                   mov r10, rsi
RVA 0x08a298e: 4889b424c0000000         mov qword ptr [rsp + 0xc0], rsi
RVA 0x08a2996: 81e3ffffff00             and ebx, 0xffffff
RVA 0x08a299c: 31f6                     xor esi, esi
RVA 0x08a299e: 4531c0                   xor r8d, r8d
RVA 0x08a29a1: 4439cf                   cmp edi, r9d
RVA 0x08a29a4: 400f96c6                 setbe sil
RVA 0x08a29a8: 410f97c0                 seta r8b
RVA 0x08a29ac: 438d3c10                 lea edi, [r8 + r10]
RVA 0x08a29b0: 4189fa                   mov r10d, edi
RVA 0x08a29b3: 4181e2ffffff00           and r10d, 0xffffff
RVA 0x08a29ba: 48c1e718                 shl rdi, 0x18
RVA 0x08a29be: 4909f9                   or r9, rdi
RVA 0x08a29c1: 4889ef                   mov rdi, rbp
RVA 0x08a29c4: 48c1ef30                 shr rdi, 0x30
```

### 2. `EasyAntiCheat_EOS.sys` (`Sec[7]` Core MBA & Dispatch `RVA 0x8A3B13..0x8A3FA1`)
```asm
RVA 0x08a3b13: 488b842480000000         mov rax, qword ptr [rsp + 0x80]
RVA 0x08a3b1b: 448d0428                 lea r8d, [rax + rbp]
RVA 0x08a3b1f: 448db5c3734500           lea r14d, [rbp + 0x4573c3]
RVA 0x08a3b26: 4189ef                   mov r15d, ebp
RVA 0x08a3b29: 4181e7c3734500           and r15d, 0x4573c3
RVA 0x08a3b30: 4501ff                   add r15d, r15d
RVA 0x08a3b33: 4529f8                   sub r8d, r15d
RVA 0x08a3b36: 458d88c0070000           lea r9d, [r8 + 0x7c0]
RVA 0x08a3b3d: 4181e1ffffff00           and r9d, 0xffffff
RVA 0x08a3b44: 488b4c2428               mov rcx, qword ptr [rsp + 0x28]
RVA 0x08a3b49: 81e116dacdff             and ecx, 0xffcdda16
RVA 0x08a3b4f: 48894c2428               mov qword ptr [rsp + 0x28], rcx
RVA 0x08a3b54: 488b8424c0000000         mov rax, qword ptr [rsp + 0xc0]
RVA 0x08a3b5c: 488b7c2408               mov rdi, qword ptr [rsp + 8]
RVA 0x08a3b61: 448d1c07                 lea r11d, [rdi + rax]
RVA 0x08a3b65: 4129cb                   sub r11d, ecx
RVA 0x08a3b68: 4489f0                   mov eax, r14d
RVA 0x08a3b6b: 25ffffff00               and eax, 0xffffff
RVA 0x08a3b70: 31ed                     xor ebp, ebp
RVA 0x08a3b72: 39842490000000           cmp dword ptr [rsp + 0x90], eax
RVA 0x08a3b79: 400f97c5                 seta bpl
RVA 0x08a3b7d: 4529fe                   sub r14d, r15d
RVA 0x08a3b80: 4101eb                   add r11d, ebp
RVA 0x08a3b83: 4181c0c3734500           add r8d, 0x4573c3
RVA 0x08a3b8a: 4181e0ffffff00           and r8d, 0xffffff
RVA 0x08a3b91: 4181e6ffffff00           and r14d, 0xffffff
RVA 0x08a3b98: 4531e4                   xor r12d, r12d
RVA 0x08a3b9b: 4539c6                   cmp r14d, r8d
RVA 0x08a3b9e: 410f97c4                 seta r12b
RVA 0x08a3ba2: 4501e3                   add r11d, r12d
RVA 0x08a3ba5: 31c9                     xor ecx, ecx
RVA 0x08a3ba7: 4181f9fd93ba00           cmp r9d, 0xba93fd
RVA 0x08a3bae: 0f92c1                   setb cl
RVA 0x08a3bb1: 48894c2420               mov qword ptr [rsp + 0x20], rcx
RVA 0x08a3bb6: 4531ff                   xor r15d, r15d
RVA 0x08a3bb9: 4139c6                   cmp r14d, eax
RVA 0x08a3bbc: 410f97c7                 seta r15b
RVA 0x08a3bc0: 428d0419                 lea eax, [rcx + r11]
RVA 0x08a3bc4: 4429f8                   sub eax, r15d
RVA 0x08a3bc7: 89c1                     mov ecx, eax
RVA 0x08a3bc9: ffc8                     dec eax
RVA 0x08a3bcb: 4189c5                   mov r13d, eax
RVA 0x08a3bce: 48c1e018                 shl rax, 0x18
RVA 0x08a3bd2: 4909c1                   or r9, rax
RVA 0x08a3bd5: 488b7c2418               mov rdi, qword ptr [rsp + 0x18]
RVA 0x08a3bda: 03bc2430010000           add edi, dword ptr [rsp + 0x130]
RVA 0x08a3be1: 488b8424f8000000         mov rax, qword ptr [rsp + 0xf8]
RVA 0x08a3be9: 2579760000               and eax, 0x7679
RVA 0x08a3bee: 29c7                     sub edi, eax
RVA 0x08a3bf0: 81e1ffffff00             and ecx, 0xffffff
RVA 0x08a3bf6: 894c2418                 mov dword ptr [rsp + 0x18], ecx
RVA 0x08a3bfa: 4181e5ffffff00           and r13d, 0xffffff
RVA 0x08a3c01: 4c8b742408               mov r14, qword ptr [rsp + 8]
RVA 0x08a3c06: 418d042e                 lea eax, [r14 + rbp]
RVA 0x08a3c0a: 050bede6ff               add eax, 0xffe6ed0b
RVA 0x08a3c0f: 25ffffff00               and eax, 0xffffff
RVA 0x08a3c14: 3b842494000000           cmp eax, dword ptr [rsp + 0x94]
RVA 0x08a3c1b: 6683d700                 adc di, 0
RVA 0x08a3c1f: 4c8b442428               mov r8, qword ptr [rsp + 0x28]
RVA 0x08a3c24: 4529c6                   sub r14d, r8d
RVA 0x08a3c27: 4101ee                   add r14d, ebp
RVA 0x08a3c2a: 4529fb                   sub r11d, r15d
RVA 0x08a3c2d: 4181c30bede6ff           add r11d, 0xffe6ed0b
RVA 0x08a3c34: 4181e3ffffff00           and r11d, 0xffffff
RVA 0x08a3c3b: 4529fe                   sub r14d, r15d
RVA 0x08a3c3e: 4181c60bede6ff           add r14d, 0xffe6ed0b
RVA 0x08a3c45: 4181e6ffffff00           and r14d, 0xffffff
RVA 0x08a3c4c: 31ed                     xor ebp, ebp
RVA 0x08a3c4e: 4539de                   cmp r14d, r11d
RVA 0x08a3c51: 400f97c5                 seta bpl
RVA 0x08a3c55: 4c8b9c24c0000000         mov r11, qword ptr [rsp + 0xc0]
RVA 0x08a3c5d: 4501e3                   add r11d, r12d
RVA 0x08a3c60: 31c9                     xor ecx, ecx
RVA 0x08a3c62: 41f7c3ffffff00           test r11d, 0xffffff
RVA 0x08a3c69: 0f94c1                   sete cl
RVA 0x08a3c6c: 4421e1                   and ecx, r12d
RVA 0x08a3c6f: 09e9                     or ecx, ebp
RVA 0x08a3c71: 01f9                     add ecx, edi
RVA 0x08a3c73: 4531e4                   xor r12d, r12d
RVA 0x08a3c76: 4139c6                   cmp r14d, eax
RVA 0x08a3c79: 488b8424b8000000         mov rax, qword ptr [rsp + 0xb8]
RVA 0x08a3c81: 49bb1649c6c3745aeea2     movabs r11, 0xa2ee5a74c3c64916
RVA 0x08a3c8b: 4a8d0418                 lea rax, [rax + r11]
RVA 0x08a3c8f: 4889442408               mov qword ptr [rsp + 8], rax
RVA 0x08a3c94: 410f97c4                 seta r12b
RVA 0x08a3c98: 4509f8                   or r8d, r15d
RVA 0x08a3c9b: 41f7d8                   neg r8d
RVA 0x08a3c9e: 31c0                     xor eax, eax
RVA 0x08a3ca0: 41f7c0ffffff00           test r8d, 0xffffff
RVA 0x08a3ca7: 0f94c0                   sete al
RVA 0x08a3caa: 4421f8                   and eax, r15d
RVA 0x08a3cad: 4409e0                   or eax, r12d
RVA 0x08a3cb0: 29c1                     sub ecx, eax
RVA 0x08a3cb2: 31c0                     xor eax, eax
RVA 0x08a3cb4: 4181fdf4121900           cmp r13d, 0x1912f4
RVA 0x08a3cbb: 0f92c0                   setb al
RVA 0x08a3cbe: 4531c0                   xor r8d, r8d
RVA 0x08a3cc1: 817c2418f5121900         cmp dword ptr [rsp + 0x18], 0x1912f5
RVA 0x08a3cc9: 410f94c0                 sete r8b
RVA 0x08a3ccd: 4423442420               and r8d, dword ptr [rsp + 0x20]
RVA 0x08a3cd2: 4109c0                   or r8d, eax
RVA 0x08a3cd5: 418d0408                 lea eax, [r8 + rcx]
RVA 0x08a3cd9: ffc8                     dec eax
RVA 0x08a3cdb: 48b9ffffffffffff0000     movabs rcx, 0xffffffffffff
RVA 0x08a3ce5: 4921c9                   and r9, rcx
RVA 0x08a3ce8: 48c1e030                 shl rax, 0x30
RVA 0x08a3cec: 4909c1                   or r9, rax
RVA 0x08a3cef: 4c8bbc2480000000         mov r15, qword ptr [rsp + 0x80]
RVA 0x08a3cf7: 488bac24a0000000         mov rbp, qword ptr [rsp + 0xa0]
RVA 0x08a3cff: 4c01fd                   add rbp, r15
RVA 0x08a3d02: 4803ac2410010000         add rbp, qword ptr [rsp + 0x110]
RVA 0x08a3d0a: 49c1ef26                 shr r15, 0x26
RVA 0x08a3d0e: 4403bc2418010000         add r15d, dword ptr [rsp + 0x118]
RVA 0x08a3d16: 4403bc2420010000         add r15d, dword ptr [rsp + 0x120]
RVA 0x08a3d1e: 4c0faf4c2448             imul r9, qword ptr [rsp + 0x48]
RVA 0x08a3d24: 4c31ce                   xor rsi, r9
RVA 0x08a3d27: 49bb070020e905000000     movabs r11, 0x5e9200007
RVA 0x08a3d31: 488b842498000000         mov rax, qword ptr [rsp + 0x98]
RVA 0x08a3d39: 4989c0                   mov r8, rax
RVA 0x08a3d3c: 4d21d8                   and r8, r11
RVA 0x08a3d3f: 4d01c0                   add r8, r8
RVA 0x08a3d42: 4c29c5                   sub rbp, r8
RVA 0x08a3d45: 488d8da0070000           lea rcx, [rbp + 0x7a0]
RVA 0x08a3d4c: 49bdffffffff3f000000     movabs r13, 0x3fffffffff
RVA 0x08a3d56: 4c21e9                   and rcx, r13
RVA 0x08a3d59: 4c01d8                   add rax, r11
RVA 0x08a3d5c: 4989c6                   mov r14, rax
RVA 0x08a3d5f: 4d21ee                   and r14, r13
RVA 0x08a3d62: 4c3bb424a8000000         cmp r14, qword ptr [rsp + 0xa8]
RVA 0x08a3d6a: 4413bc24b0000000         adc r15d, dword ptr [rsp + 0xb0]
RVA 0x08a3d72: 4c8ba42448010000         mov r12, qword ptr [rsp + 0x148]
RVA 0x08a3d7a: 488b7c2408               mov rdi, qword ptr [rsp + 8]
RVA 0x08a3d7f: 49893c24                 mov qword ptr [r12], rdi
```

### 3. `eacfn.sys` (`Sec[7]` Affine `0x7C084` MBA Dispatcher `RVA 0x1CD7A15..0x1CD7A7D`)
```asm
RVA 0x1cd7a15: 49898c2490010000         mov qword ptr [r12 + 0x190], rcx
RVA 0x1cd7a1d: 4969c112f1fbff           imul rax, r9, -0x40eee
RVA 0x1cd7a24: 488d8884c00700           lea rcx, [rax + 0x7c084]
RVA 0x1cd7a2b: 480fafce                 imul rcx, rsi
RVA 0x1cd7a2f: 4829c8                   sub rax, rcx
RVA 0x1cd7a32: 488d90babd0800           lea rdx, [rax + 0x8bdba]
RVA 0x1cd7a39: 480faf55f0               imul rdx, qword ptr [rbp - 0x10]
RVA 0x1cd7a3e: 4829d0                   sub rax, rdx
RVA 0x1cd7a41: 488db0e5b5ffff           lea rsi, [rax - 0x4a1b]
RVA 0x1cd7a48: 480faff7                 imul rsi, rdi
RVA 0x1cd7a4c: 4829f0                   sub rax, rsi
RVA 0x1cd7a4f: 4805bd6a0600             add rax, 0x66abd
RVA 0x1cd7a55: 490fafc3                 imul rax, r11
RVA 0x1cd7a59: 4969f9ee0e0400           imul rdi, r9, 0x40eee
RVA 0x1cd7a60: 4803bd10ffffff           add rdi, qword ptr [rbp - 0xf0]
RVA 0x1cd7a67: 4801cf                   add rdi, rcx
RVA 0x1cd7a6a: 4801d7                   add rdi, rdx
RVA 0x1cd7a6d: 4801f7                   add rdi, rsi
RVA 0x1cd7a70: 4801f8                   add rax, rdi
RVA 0x1cd7a73: 480532b73c00             add rax, 0x3cb732
RVA 0x1cd7a79: 4889ec                   mov rsp, rbp
RVA 0x1cd7a7c: 5d                       pop rbp
```
