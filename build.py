#!/usr/bin/env python3
import subprocess, struct, random

FLAG = b"Spark{fr34ky_fr34kish_funky_m4lw4r3_4n4lysis_6699}"
N = len(FLAG)

JT_OFF, TAB_OFF, BC_OFF = 0x110, 0x150, 0x190
BC_LEN = N * 22 + 1
OUT_OFF = BC_OFF + BC_LEN
OUT_LEN = 64
BLOB_LEN = ((OUT_OFF + OUT_LEN + 7) // 8) * 8

DELTA = 0x9E3779B9

def xtea_dec_block(v0, v1, k):
    s = (DELTA * 32) & 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & 0xFFFFFFFF
        s = (s - DELTA) & 0xFFFFFFFF
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & 0xFFFFFFFF
    return v0, v1

def xtea_enc_block(v0, v1, k):
    s = 0
    for _ in range(32):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & 0xFFFFFFFF
        s = (s + DELTA) & 0xFFFFFFFF
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & 0xFFFFFFFF
    return v0, v1

def derive_key():
    a, b = 0x1F2E3D4C, 0x0A5C36F1
    for _ in range(3):
        a = ((a << 7) | (a >> 25)) & 0xFFFFFFFF
        b ^= a
    return [a ^ 0x5A5A5A5A, b, (a + b) & 0xFFFFFFFF,
            (((b << 9) ^ (a >> 3)) & 0xFFFFFFFF)]

def rol8(b, n): return ((b << n) | (b >> (8 - n))) & 0xFF if n else b
def ror8(b, n): return ((b >> n) | (b << (8 - n))) & 0xFF if n else b

subprocess.run(["nasm", "-f", "elf64", "vm.asm", "-o", "vm.o",
                "-DJT_OFF=%d" % JT_OFF, "-DBC_OFF=%d" % BC_OFF,
                "-DTAB_OFF=%d" % TAB_OFF, "-DBC_LEN=%d" % BC_LEN,
                "-DOUT_OFF=%d" % OUT_OFF], check=True)
subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", "vm.o", "vm.bin"], check=True)

syms = {}
for line in subprocess.check_output(["nm", "vm.o"]).decode().splitlines():
    if line.strip():
        addr, _t, name = line.split()
        syms[name] = int(addr, 16)
assert syms["start"] == 0 and syms["op_halt"] < JT_OFF

code = open("vm.bin", "rb").read()
assert code[0] == 0x55 or code[:3] in (b"\x49\x89\xe7", b"\x4c\x8b\xe7"), "vm.bin does not begin at 'start'"
assert len(code) <= JT_OFF

blob = bytearray(code)
blob += b"\x90" * (JT_OFF - len(blob))
blob += bytes(BLOB_LEN - len(blob))

key1 = sum(blob[:64]) & 0xFF

handlers = ["op_push", "op_pushk", "op_add", "op_xor", "op_rol",
            "op_mul", "op_and", "op_emit", "op_halt"]
jt = [syms[h] for h in handlers] + [syms["op_halt"]] * 7
blob[JT_OFF:JT_OFF + 64] = b"".join(struct.pack("<i", o) for o in jt)

T = bytearray(64)
positions = set()
for i in range(N):
    p = (7 * i + 13) & 63
    positions.add(p)
    T[p] = ror8(FLAG[i] ^ ((0x37 * i + 0x5A) & 0xFF), i % 8)
random.seed(1337)
for j in range(64):
    if j not in positions:
        T[j] = random.randrange(1, 256)
tab = bytes(rol8(T[j], (key1 + 5 * j) & 7) ^ ((key1 + j) & 0xFF) for j in range(64))
blob[TAB_OFF:TAB_OFF + 64] = tab

OP = {"PUSH": 0, "PUSHK": 1, "ADD": 2, "XOR": 3, "ROL": 4, "MUL": 5,
      "AND": 6, "EMIT": 7, "HALT": 8}
def enc_op(op): return OP[op] ^ 0xA5
bc = bytearray()
for i in range(N):
    bc += bytes([enc_op("PUSH"), i])
    bc += bytes([enc_op("MUL"), 7])
    bc += bytes([enc_op("PUSH"), 13])
    bc += bytes([enc_op("ADD")])
    bc += bytes([enc_op("AND"), 0x3F])
    bc += bytes([enc_op("PUSHK"), (7 * i + 13) & 0x3F])
    bc += bytes([enc_op("ROL"), i % 8])
    bc += bytes([enc_op("PUSH"), i])
    bc += bytes([enc_op("MUL"), 0x37])
    bc += bytes([enc_op("PUSH"), 0x5A])
    bc += bytes([enc_op("ADD")])
    bc += bytes([enc_op("XOR")])
    bc += bytes([enc_op("EMIT")])
bc.append(enc_op("HALT"))
assert len(bc) == BC_LEN
blob[BC_OFF:BC_OFF + BC_LEN] = bytes(b ^ key1 ^ ((0x9E * i) & 0xFF)
                                     for i, b in enumerate(bc))

k = derive_key()
enc = bytearray()
for off in range(0, BLOB_LEN, 8):
    v0, v1 = struct.unpack("<II", bytes(blob[off:off + 8]))
    v0, v1 = xtea_enc_block(v0, v1, k)
    enc += struct.pack("<II", v0, v1)

with open("payload.h", "w") as f:
    f.write("#include <stddef.h>\n#define PAYLOAD_LEN %d\n" % BLOB_LEN)
    f.write("static const unsigned char payload[PAYLOAD_LEN] = {")
    f.write(",".join("0x%02x" % b for b in enc))
    f.write("};\n")
print("[+] payload.h written, key1=%d, blob=%d bytes" % (key1, BLOB_LEN))

def _selftest(enc_bytes, key):
    bl = bytearray()
    for off in range(0, len(enc_bytes), 8):
        v0, v1 = struct.unpack("<II", bytes(enc_bytes[off:off + 8]))
        v0, v1 = xtea_dec_block(v0, v1, key)
        bl += struct.pack("<II", v0, v1)

    k1 = sum(bl[:64]) & 0xFF
    assert k1 == key1, "key1 mismatch"

    bc2 = bytes(b ^ k1 ^ ((0x9E * i) & 0xFF)
                for i, b in enumerate(bl[BC_OFF:BC_OFF + BC_LEN]))
    tb = bl[TAB_OFF:TAB_OFF + 64]

    st, pc, out = [], 0, bytearray()
    while True:
        op = (bc2[pc] ^ 0xA5) & 0x0F
        pc += 1
        if op == 0:
            st.append(bc2[pc]); pc += 1
        elif op == 1:
            idx = bc2[pc]; pc += 1
            v = tb[idx] ^ ((k1 + idx) & 0xFF)
            st.append(ror8(v, (k1 + 5 * idx) & 7))
        elif op == 2:
            st.append(st.pop() + st.pop())
        elif op == 3:
            st.append(st.pop() ^ st.pop())
        elif op == 4:
            st.append(rol8(st.pop() & 0xFF, bc2[pc])); pc += 1
        elif op == 5:
            st.append(st.pop() * bc2[pc]); pc += 1
        elif op == 6:
            st.append(st.pop() & bc2[pc]); pc += 1
        elif op == 7:
            out.append(st.pop() & 0xFF)
        else:
            break
    return bytes(out)

assert _selftest(enc, k) == FLAG, "self-test failed"
print("[+] self-test OK")
