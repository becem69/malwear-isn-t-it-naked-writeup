import struct

data = open("SUS", "rb").read()

# Payload is at vaddr 0x478020 -> file offset 0x78020
PAYLOAD_FOFF = 0x78020
PAYLOAD_SIZE = 0x610

payload = data[PAYLOAD_FOFF:PAYLOAD_FOFF + PAYLOAD_SIZE]

# --- Step 2: Derive XTEA key ---
a, b = 0x1F2E3D4C, 0x0A5C36F1
for _ in range(3):
    a = ((a << 7) | (a >> 25)) & 0xFFFFFFFF
    b ^= a
k = [a ^ 0x5A5A5A5A, b, (a + b) & 0xFFFFFFFF, ((b << 9) ^ (a >> 3)) & 0xFFFFFFFF]
print(f"[*] XTEA key: {[hex(x) for x in k]}")

# --- Step 3: XTEA decrypt ---
DELTA = 0x9E3779B9

def dec(v0, v1):
    s = 0xC6EF3720
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & 0xFFFFFFFF
        s  = (s - DELTA) & 0xFFFFFFFF
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & 0xFFFFFFFF
    return v0, v1

blob = bytearray()
for off in range(0, PAYLOAD_SIZE, 8):
    v0, v1 = struct.unpack("<II", payload[off:off + 8])
    v0, v1 = dec(v0, v1)
    blob += struct.pack("<II", v0, v1)

print(f"[*] First bytes of blob: {blob[:8].hex()}  (expect: 555341...)")

# --- Step 4: VM layout constants (confirmed from shellcode disasm) ---
BC_OFF  = 0x190
TAB_OFF = 0x150
JT_OFF  = 0x110
BC_LEN  = 0x44D
OUT_OFF = 0x5dd

# key1 = sum of first 64 bytes of code
key1 = sum(blob[:64]) & 0xFF
print(f"[*] key1 = {key1:#x}")

# Decrypt bytecode
bc = bytearray(b ^ key1 ^ ((0x9E * i) & 0xFF) for i, b in enumerate(blob[BC_OFF:BC_OFF + BC_LEN]))

# Constant table (64 bytes)
tab = blob[TAB_OFF:TAB_OFF + 64]

def rol8(b, n): n &= 7; return ((b << n) | (b >> (8 - n))) & 0xFF if n else b & 0xFF
def ror8(b, n): n &= 7; return ((b >> n) | (b << (8 - n))) & 0xFF if n else b & 0xFF

# Jump table: 16 signed dwords - these are RELATIVE offsets within the blob
# The shellcode does: lea rbx, [rbp + rax*1 + 0x0]  where rax = jt[op]
# So each entry is a byte offset into the blob
jt = [int.from_bytes(blob[JT_OFF + 4*i:JT_OFF + 4*i + 4], 'little', signed=True) for i in range(16)]
print(f"[*] Jump table (blob-relative offsets): {[hex(x & 0xFFFF) for x in jt]}")

# Handler offsets come directly from the jump table (opcode index = VM opcode)
PUSH  = jt[0] & 0xFFFF
PUSHK = jt[1] & 0xFFFF
ADD   = jt[2] & 0xFFFF
XOR   = jt[3] & 0xFFFF
ROL   = jt[4] & 0xFFFF
MUL   = jt[5] & 0xFFFF
AND   = jt[6] & 0xFFFF
EMIT  = jt[7] & 0xFFFF
HALT  = jt[8] & 0xFFFF

# --- Step 5: Emulate the VM ---
st, pc, out = [], 0, bytearray()
max_steps = 1000000
steps = 0

while steps < max_steps:
    steps += 1
    raw_op = bc[pc] ^ 0xA5
    op = raw_op & 0x0F
    pc += 1
    t = jt[op] & 0xFFFF  # treat as unsigned blob offset

    if t == PUSH:
        st.append(bc[pc]); pc += 1
    elif t == PUSHK:
        idx = bc[pc]; pc += 1
        v = tab[idx]
        v ^= (key1 + idx) & 0xFF
        v = ror8(v, (key1 + 5 * idx) & 7)
        st.append(v)
    elif t == ADD:
        c, a = st.pop(), st.pop()
        st.append((a + c) & 0xFF)
    elif t == XOR:
        c, a = st.pop(), st.pop()
        st.append(a ^ c)
    elif t == ROL:
        n = bc[pc]; pc += 1
        st.append(rol8(st.pop() & 0xFF, n))
    elif t == MUL:
        n = bc[pc]; pc += 1
        st.append((st.pop() * n) & 0xFF)
    elif t == AND:
        n = bc[pc]; pc += 1
        st.append(st.pop() & n)
    elif t == EMIT:
        out.append(st.pop() & 0xFF)
    elif t == HALT:
        print(f"[*] HALT at pc={pc-1}, {len(out)} bytes emitted")
        break
    else:
        print(f"[!] Unknown handler t={hex(t)} op={op} at pc={pc-1}, stack={st}")
        break

if steps >= max_steps:
    print(f"[!] Step limit reached, {len(out)} bytes emitted so far")

print(f"\n[+] Flag: {out.decode(errors='replace')}")
print(f"[+] Raw bytes: {out.hex()}")
