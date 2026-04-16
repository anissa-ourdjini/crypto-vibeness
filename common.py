import base64
import binascii
import hashlib
import json
import socket
from typing import Optional

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5050
BUFFER_SIZE = 65536

COLOR_RESET = "\033[0m"
COLOR_PALETTE = [
    "\033[31m",
    "\033[32m",
    "\033[33m",
    "\033[34m",
    "\033[35m",
    "\033[36m",
    "\033[91m",
    "\033[92m",
    "\033[93m",
    "\033[94m",
]


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def safe_b64d(data: str) -> Optional[bytes]:
    try:
        return b64d(data)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return None


def valid_public_key(pub: object) -> bool:
    if not isinstance(pub, dict):
        return False
    if "n" not in pub or "e" not in pub:
        return False
    try:
        n = int(pub["n"])
        e = int(pub["e"])
    except (TypeError, ValueError):
        return False
    if n <= 0 or e <= 2:
        return False
    if e % 2 == 0:
        return False
    if n <= e:
        return False
    if n.bit_length() < 512:
        return False
    return True


def deterministic_color(username: str) -> str:
    digest = hashlib.sha256(username.encode("utf-8")).digest()
    idx = digest[0] % len(COLOR_PALETTE)
    return COLOR_PALETTE[idx]


def json_send(conn: socket.socket, payload: dict) -> None:
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    conn.sendall(data)


def json_recv(buffer: bytearray, conn: socket.socket) -> Optional[dict]:
    while True:
        idx = buffer.find(b"\n")
        if idx != -1:
            line = bytes(buffer[:idx])
            del buffer[: idx + 1]
            if not line:
                continue
            return json.loads(line.decode("utf-8"))
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
            return None
        buffer.extend(chunk)
