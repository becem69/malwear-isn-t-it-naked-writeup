# malware? isn't it naked?

**CTF:** SPARK CTF  
**Category:** Reverse Engineering  
**Difficulty:** Insane  
**Author:** becem69 😝  
**Flag:** `Spark{fr34ky_fr34kish_funky_m4lw4r3_4n4lysis_6699}`

---

## Overview

The challenge gives you a single binary called `SUS`. The goal is to recover the flag it computes at runtime, using only static analysis. The binary is never executed during the solution process. Everything is reconstructed in Python.

The binary is a 64-bit ELF, statically linked with libc, and fully stripped. It weighs around 660 KB. It contains an encrypted shellcode payload that implements a tiny custom virtual machine. The flag is assembled one byte at a time inside that VM and never exists as a contiguous string anywhere in the binary.

---

## Files

| File | Description |
|------|-------------|
| `SUS` | The challenge binary (x86-64 ELF, statically linked, stripped) |
| `solve.py` | Full Python emulator that derives the key, decrypts the payload, and emulates the VM |
| `build.py` | Build script used to generate the challenge |
| `loader.c` | C loader stub |
| `vm.asm` | VM shellcode source in assembly |

---

## Solution Walkthrough

### Step 1 - Initial Recon

```
$ file SUS
SUS: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

```
$ readelf -S -W SUS
```

Key sections:

| Section | Virtual Address | File Offset | Notes |
|---------|----------------|-------------|-------|
| `.text` | `0x401100` | `0x001100` | Size: `0x764bd` |
| `.rodata` | `0x478000` | `0x078000` | Contains encrypted payload |
| `.init_array` | `0x4a0138` | `0x0a0138` | 3 constructor pointers |
| `.data` | `0x4a40c0` | `0x0a40c0` | Runtime key storage |

The file offset formula for this binary is:

```
file_offset = vaddr - 0x400000
```

Since the binary is stripped, interesting functions are found by reading `.init_array` and tracing from the entry point.

The three `.init_array` entries:

```python
import struct
data = open('SUS', 'rb').read()
for i in range(3):
    addr = struct.unpack_from('<Q', data, 0x0a0138 + i*8)[0]
    print(hex(addr))
# 0x401750  -> libc internal
# 0x401785  -> XTEA key derivation constructor
# 0x401620  -> libc internal
```

The entry point is `0x401660`. It calls `main` at `0x4018db`.

---

### Step 2 - Reading main (0x4018db)

```
$ objdump -d -M intel --start-address 0x4018db --stop-address 0x4019f4 SUS
```

What `main` does in order:

1. **Anti-debug check** via `ptrace(PTRACE_TRACEME, 0, 0, 0)`. If the return value is `-1` (already being traced), main returns immediately. This prevents naive debugger attachment.

2. **Allocate buffer:** `malloc(0x618)`.

3. **Copy encrypted payload:** 0x610 bytes from vaddr `0x478020` (file offset `0x78020`) into the buffer, using a `rep movsq` loop.

4. **XTEA decrypt loop:** for each 8-byte block at offsets `0..0x610`, call the XTEA decryption routine at `0x4017f2`.

5. **mmap a RWX page:** `mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`.

6. **Copy decrypted payload** into the mmap region.

7. **`call rax`** to execute the shellcode.

The encrypted payload is 0x610 (1552) bytes stored at file offset `0x78020`.

---

### Step 3 - Deriving the XTEA Key (constructor at 0x401785)

```
$ objdump -d -M intel --start-address 0x401785 --stop-address 0x4017f2 SUS
```

The constructor seeds two 32-bit values and runs a 3-iteration mixing loop:

```python
a, b = 0x1F2E3D4C, 0x0A5C36F1
for _ in range(3):
    a = ((a << 7) | (a >> 25)) & 0xFFFFFFFF   # rol32(a, 7)
    b ^= a
k = [
    a ^ 0x5A5A5A5A,
    b,
    (a + b) & 0xFFFFFFFF,
    ((b << 9) ^ (a >> 3)) & 0xFFFFFFFF
]
```

Result:

```
k = [0xf3d9bf9d, 0xbb9272f2, 0x651658b9, 0x31d598b8]
```

The key is never stored as a constant in the binary. It is computed at runtime before `main` runs, via this constructor.

---

### Step 4 - XTEA Decrypting the Payload

```
$ objdump -d -M intel --start-address 0x4017f2 --stop-address 0x401785 SUS
```

Standard XTEA block decryption: 32 rounds, `DELTA = 0x9E3779B9`, starting sum `0xC6EF3720` (which is `DELTA * 32`).

```python
DELTA = 0x9E3779B9

def dec(v0, v1):
    s = 0xC6EF3720
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & 0xFFFFFFFF
        s  = (s - DELTA) & 0xFFFFFFFF
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & 0xFFFFFFFF
    return v0, v1

payload = data[0x78020:0x78020 + 0x610]
blob = bytearray()
for off in range(0, 0x610, 8):
    v0, v1 = struct.unpack("<II", payload[off:off + 8])
    blob += struct.pack("<II", *dec(v0, v1))
```

Verification: the first three bytes of the decrypted blob are `49 89 e7` (`mov r15, rsp`), which is the expected prologue of a position-independent shellcode. This confirms both the payload location and the key.

The decrypted blob is saved to `blob.bin`.

---

### Step 5 - Reversing the VM Shellcode (blob.bin)

```
$ objdump -D -b binary -m i386:x86-64 -M intel blob.bin
```

The shellcode is position-independent. It uses the classic `call/pop` trick to load its own base address into `rbp`. The prologue also saves all callee-saved registers so the caller's state is preserved on return:

```asm
0x00:  55              push rbp          ; save callee-saved registers
0x01:  53              push rbx
0x02:  41 54           push r12
0x04:  41 55           push r13
0x06:  41 56           push r14
0x08:  41 57           push r15
0x0a:  4c 8d 3c 24     mov r15, rsp      ; save stack pointer for HALT
0x0e:  e8 00 00 00 00  call 0x13         ; push rip+5
0x13:  5d              pop rbp           ; rbp = base address of blob
```

All internal layout offsets are visible directly from the disassembly as `[rbp + constant]` references:

| Blob Offset | Name | Purpose |
|-------------|------|---------|
| `0x000` | VM code | First 64 bytes are tamper-protected |
| `0x110` | Jump table | 16 signed dwords (blob-relative offsets to handlers) |
| `0x150` | Constant table | 64 bytes of obfuscated constants |
| `0x190` | Bytecode | Encrypted bytecode, 0x44d (1101) bytes |
| `0x5dd` | Output buffer | Flag is written here byte by byte |

**Tamper protection (key1)**

Before decrypting the bytecode, the shellcode sums the first 64 bytes of its own code region to produce an 8-bit value called `key1`:

```python
key1 = sum(blob[0:64]) & 0xFF   # = 0xd3
```

If any byte in that first 64-byte region is patched (for example to bypass the `ptrace` check), `key1` changes, which silently corrupts both the bytecode decryption and the constant table lookups. This is a clever way to punish static patching.

**Bytecode decryption**

```python
bc = bytearray(
    b ^ key1 ^ ((0x9E * i) & 0xFF)
    for i, b in enumerate(blob[0x190:0x190 + 0x44D])
)
```

**Instruction dispatch**

```python
op = (bc[pc] ^ 0xA5) & 0x0F
pc += 1
handler_offset = jt[op]   # signed dword from jump table
jmp rbp + handler_offset  # absolute address
```

**VM instruction set**

| Opcode | Handler offset | Mnemonic | Behavior |
|--------|---------------|----------|----------|
| 0 | `0x86` | PUSH | Push next literal bytecode byte onto stack |
| 1 | `0x8f` | PUSHK | Push decoded constant table entry (obfuscated with key1) |
| 2 | `0xb3` | ADD | Pop two, push `a + b` |
| 3 | `0xba` | XOR | Pop two, push `a ^ b` |
| 4 | `0xc1` | ROL | Pop one, rotate left by next immediate byte |
| 5 | `0xcd` | MUL | Pop one, multiply by next immediate byte |
| 6 | `0xda` | AND | Pop one, AND with next immediate byte |
| 7 | `0xe9` | EMIT | Pop one, write to output buffer (flag bytes come out here) |
| 8+ | `0xf5` | HALT | Restore callee-saved registers and `rsp`, return |

The constant table entries accessed by PUSHK are obfuscated per-entry:

```python
v = tab[idx]
v ^= (key1 + idx) & 0xFF
v = ror8(v, (key1 + 5 * idx) & 7)
```

---

### Step 6 - Python Emulator (solve.py)

`solve.py` ties everything together:

1. Read `SUS`, extract 0x610 bytes at file offset `0x78020`.
2. Derive the XTEA key from the two seed constants.
3. XTEA-decrypt the payload into `blob.bin`.
4. Read the jump table, constant table, and bytecode from their fixed offsets.
5. Compute `key1` from `blob[0:64]`.
6. Decrypt the bytecode with `key1` and the rolling `0x9E` counter.
7. Emulate the VM instruction by instruction until HALT.
8. Print the output buffer as ASCII.

Running it:

```
$ python3 solve.py
[*] XTEA key: ['0xf3d9bf9d', '0xbb9272f2', '0x651658b9', '0x31d598b8']
[*] First bytes of blob: 5553415441554156  (expect: 555341...)
[*] key1 = 0xd3
[*] Jump table: ['0x86', '0x8f', '0xb3', '0xba', '0xc1', '0xcd', '0xda', '0xe9', '0xf5', ...]
[*] HALT at pc=1100, 50 bytes emitted
[+] Flag: Spark{fr34ky_fr34kish_funky_m4lw4r3_4n4lysis_6699}
```

The flag is 50 bytes including the braces.

---

## Why "Insane" Tier

Every layer of this challenge is designed to resist the obvious approaches:

- The flag never appears in plaintext anywhere in the binary or payload. It is assembled one byte at a time by EMIT instructions so it never exists as a contiguous string in memory until execution ends.
- The XTEA key is not a constant. It is computed at runtime by a constructor that runs before `main`, making simple string searches useless.
- The shellcode is position-independent via the `call+pop rbp` trick, so all internal references are blob-relative and hide the structure from naive linear scans.
- `key1` is derived from the VM code bytes themselves. Any patch to the first 64 bytes of the blob (for example to skip the `ptrace` anti-debug check) changes `key1`, which silently corrupts both the bytecode decryption and every constant table lookup. You get garbage output with no obvious error.
- The constant table uses a per-entry obfuscation scheme that depends on both `key1` and the entry index, so reversing one entry does not help with the others.
- The dispatch mechanism uses a jump table of blob-relative dword offsets rather than a direct opcode-to-handler mapping, which hides the handler structure.

Static analysis and a Python emulator are sufficient to solve this without ever running the binary, defeating ptrace, or using a debugger.

---

## Key Addresses and Offsets (Quick Reference)

| Symbol | Value | Notes |
|--------|-------|-------|
| Entry point | `0x401660` | Calls main via hardcoded `mov rdi` |
| `main` | `0x4018db` | Anti-debug, decrypt, map, execute |
| XTEA key constructor | `0x401785` | Seeds: `0x1F2E3D4C`, `0x0A5C36F1` |
| XTEA decrypt routine | `0x4017f2` | 32-round, DELTA `0x9E3779B9` |
| Encrypted payload vaddr | `0x478020` | File offset `0x78020`, size `0x610` |
| XTEA key storage | `0x4a5ab0` | Four 32-bit words at runtime |
| Blob: jump table | `+0x110` | 16 signed dwords |
| Blob: constant table | `+0x150` | 64 bytes |
| Blob: bytecode | `+0x190` | `0x44d` bytes |
| Blob: output buffer | `+0x5dd` | Flag written here |
| `key1` | `0xd3` | `sum(blob[0:64]) & 0xFF` |
| XTEA key | `[0xf3d9bf9d, 0xbb9272f2, 0x651658b9, 0x31d598b8]` | Derived at runtime |

---

## Author

**becem69 😝**

Challenge designed, built, and solved by becem69 for SPARK CTF.  
If you have questions, feedback, or just want to talk reversing, feel free to reach out.
