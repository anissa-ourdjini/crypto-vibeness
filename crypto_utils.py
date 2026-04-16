import hashlib
import secrets
from typing import Tuple


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _modinv(a: int, n: int) -> int:
    g, x, _ = _egcd(a, n)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % n


def _is_probable_prime(n: int, rounds: int = 10) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def rsa_generate_keypair(bits: int = 1024) -> Tuple[dict, dict]:
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e != 0:
            d = _modinv(e, phi)
            return {"n": n, "e": e}, {"n": n, "d": d}


def rsa_encrypt(pub: dict, data: bytes) -> bytes:
    m = int.from_bytes(data, "big")
    n = int(pub["n"])
    e = int(pub["e"])
    if m >= n:
        raise ValueError("message too large")
    c = pow(m, e, n)
    size = (n.bit_length() + 7) // 8
    return c.to_bytes(size, "big")


def rsa_decrypt(priv: dict, data: bytes) -> bytes:
    c = int.from_bytes(data, "big")
    n = int(priv["n"])
    d = int(priv["d"])
    m = pow(c, d, n)
    size = (m.bit_length() + 7) // 8
    return m.to_bytes(size, "big")


def rsa_sign(priv: dict, data: bytes) -> bytes:
    digest = hashlib.sha256(data).digest()
    h = int.from_bytes(digest, "big")
    n = int(priv["n"])
    d = int(priv["d"])
    s = pow(h, d, n)
    size = (n.bit_length() + 7) // 8
    return s.to_bytes(size, "big")


def rsa_verify(pub: dict, data: bytes, sig: bytes) -> bool:
    digest = hashlib.sha256(data).digest()
    h = int.from_bytes(digest, "big")
    n = int(pub["n"])
    e = int(pub["e"])
    s = int.from_bytes(sig, "big")
    return pow(s, e, n) == h


def _tea_encrypt_block(block: bytes, key: bytes) -> bytes:
    v0 = int.from_bytes(block[:4], "big")
    v1 = int.from_bytes(block[4:], "big")
    k = [int.from_bytes(key[i : i + 4], "big") for i in range(0, 16, 4)]
    delta = 0x9E3779B9
    summ = 0
    for _ in range(32):
        summ = (summ + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + summ) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + summ) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def _tea_decrypt_block(block: bytes, key: bytes) -> bytes:
    v0 = int.from_bytes(block[:4], "big")
    v1 = int.from_bytes(block[4:], "big")
    k = [int.from_bytes(key[i : i + 4], "big") for i in range(0, 16, 4)]
    delta = 0x9E3779B9
    summ = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + summ) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + summ) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        summ = (summ - delta) & 0xFFFFFFFF
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def tea_encrypt_cbc(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    iv = secrets.token_bytes(8)
    pad = 8 - (len(plaintext) % 8)
    plaintext += bytes([pad]) * pad
    prev = iv
    out = bytearray()
    for i in range(0, len(plaintext), 8):
        block = plaintext[i : i + 8]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = _tea_encrypt_block(xored, key)
        out.extend(enc)
        prev = enc
    return iv, bytes(out)


def tea_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i : i + 8]
        dec = _tea_decrypt_block(block, key)
        out.extend(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = block
    if not out:
        return b""
    pad = out[-1]
    if pad < 1 or pad > 8:
        raise ValueError("Invalid padding")
    return bytes(out[:-pad])
