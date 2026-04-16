#!/usr/bin/env python3
import argparse
import getpass
import hashlib
import json
import os
import secrets
import socket
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from common_utils import b64d, b64e, deterministic_color, json_recv, json_send, safe_b64d, valid_public_key

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5050
COLOR_RESET = "\033[0m"
COLOR_DM_TAG = "\033[96m"
USERS_DIR = Path("users")
REPLAY_WINDOW_SECONDS = 120
MAX_SEEN_MESSAGE_IDS = 2048


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


class ChatClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.username = ""
        self.current_room = "general"
        self.my_color = ""
        self.stop_event = threading.Event()
        self.print_lock = threading.Lock()
        self.pubkey: dict = {}
        self.privkey: dict = {}
        self.peer_pubkeys: Dict[str, dict] = {}
        self.session_keys: Dict[str, bytes] = {}
        self.seen_message_ids: Dict[str, float] = {}
        self.room_protection: Dict[str, bool] = {"general": False}
        self.user_dir = USERS_DIR

    def safe_print(self, msg: str) -> None:
        with self.print_lock:
            print(msg)

    def _make_msg_meta(self) -> Tuple[str, int]:
        return secrets.token_hex(16), int(time.time())

    def _validate_and_track_msg(self, sender: str, msg_id: str, timestamp: int) -> bool:
        if not msg_id:
            return False
        now = int(time.time())
        if timestamp > now + 10:
            return False
        if timestamp < now - REPLAY_WINDOW_SECONDS:
            return False

        key = f"{sender}:{msg_id}"
        if key in self.seen_message_ids:
            return False
        self.seen_message_ids[key] = float(timestamp)

        cutoff = now - REPLAY_WINDOW_SECONDS
        stale = [k for k, ts in self.seen_message_ids.items() if ts < cutoff]
        for k in stale:
            del self.seen_message_ids[k]
        if len(self.seen_message_ids) > MAX_SEEN_MESSAGE_IDS:
            oldest = min(self.seen_message_ids, key=self.seen_message_ids.get)
            del self.seen_message_ids[oldest]
        return True

    def peer_keys_path(self) -> Path:
        return self.user_dir / "known_pubkeys.json"

    def format_room_name(self, room: str) -> str:
        if self.room_protection.get(room, False):
            return f"\U0001f512 {room}"
        return room

    def load_known_peer_keys(self) -> Dict[str, dict]:
        path = self.peer_keys_path()
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

        if not isinstance(payload, dict):
            return {}
        out: Dict[str, dict] = {}
        for username, pub in payload.items():
            if not isinstance(username, str):
                continue
            if username == self.username:
                continue
            if valid_public_key(pub):
                out[username] = pub
        return out

    def save_known_peer_keys(self) -> None:
        path = self.peer_keys_path()
        serializable = {u: self.peer_pubkeys[u] for u in sorted(self.peer_pubkeys) if u != self.username}
        with path.open("w", encoding="utf-8") as f:
            json.dump(serializable, f, separators=(",", ":"), ensure_ascii=True)

    def remember_peer_key(self, username: str, pub: dict) -> None:
        if username == self.username:
            return
        self.peer_pubkeys[username] = pub
        self.save_known_peer_keys()

    def load_or_generate_keys(self, username: str) -> Tuple[dict, dict]:
        base_dir = USERS_DIR / username
        base_dir.mkdir(parents=True, exist_ok=True)
        base_name = base_dir / "identity"
        pub_path = base_name.with_suffix(".pub")
        priv_path = base_name.with_suffix(".priv")

        if pub_path.exists() and priv_path.exists():
            with pub_path.open("r", encoding="utf-8") as f:
                pub = json.load(f)
            with priv_path.open("r", encoding="utf-8") as f:
                priv = json.load(f)
            return pub, priv

        self.safe_print("Generating RSA keypair for this user (first run)...")
        pub, priv = rsa_generate_keypair(1024)
        with pub_path.open("w", encoding="utf-8") as f:
            json.dump(pub, f)
        with priv_path.open("w", encoding="utf-8") as f:
            json.dump(priv, f)
        return pub, priv

    def connect(self) -> None:
        self.username = input("Username: ").strip()
        if not self.username:
            raise SystemExit("Username is required")
        self.user_dir = USERS_DIR / self.username
        self.pubkey, self.privkey = self.load_or_generate_keys(self.username)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        self.sock = sock

        json_send(sock, {"type": "hello", "username": self.username, "public_key": self.pubkey})
        challenge = json_recv(self.buffer, sock)
        if not challenge:
            raise SystemExit("Server disconnected")
        if challenge.get("type") == "error":
            raise SystemExit(challenge.get("message", "Server error"))
        if challenge.get("type") != "auth_challenge":
            raise SystemExit("Unexpected auth handshake")

        existing = bool(challenge.get("existing"))
        rules = challenge.get("rules", {})
        if existing:
            password = getpass.getpass("Password: ")
        else:
            self.safe_print("Creating a new account.")
            self.safe_print(f"Rules: {json.dumps(rules)}")
            password = getpass.getpass("Choose password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                raise SystemExit("Password mismatch")

        json_send(sock, {"type": "auth_submit", "password": password})

        while True:
            auth_reply = json_recv(self.buffer, sock)
            if not auth_reply:
                raise SystemExit("Server disconnected")
            typ = auth_reply.get("type")
            if typ == "password_strength":
                bits = auth_reply.get("entropy_bits")
                level = auth_reply.get("strength_level", "unknown")
                self.safe_print(f"Password entropy estimate: {bits} bits ({level})")
                continue
            if typ == "error":
                raise SystemExit(auth_reply.get("message", "Authentication failed"))
            if typ == "auth_ok":
                self.my_color = auth_reply.get("color", "")
                self.current_room = auth_reply.get("current_room", "general")
                self.peer_pubkeys = self.load_known_peer_keys()
                directory = auth_reply.get("public_directory", {}) or {}
                if isinstance(directory, dict):
                    for username, pub in directory.items():
                        if isinstance(username, str) and valid_public_key(pub) and username != self.username:
                            self.peer_pubkeys[username] = pub
                self.save_known_peer_keys()
                rooms = auth_reply.get("rooms", [])
                self.print_rooms(rooms)
                self.safe_print(f"Connected. Current room: {self.format_room_name(self.current_room)}")
                break
            raise SystemExit("Unexpected authentication response")

    def print_rooms(self, rooms: list) -> None:
        if not rooms:
            self.safe_print("No rooms available.")
            return
        self.room_protection = {
            str(r.get("name", "")).strip(): bool(r.get("protected", False))
            for r in rooms
            if str(r.get("name", "")).strip()
        }
        self.safe_print("Rooms:")
        for r in rooms:
            marker = "[P]" if r.get("protected") else "[ ]"
            self.safe_print(f"  {marker} {r.get('name')} ({r.get('members')} users)")

    def show_help(self) -> None:
        self.safe_print(
            "\nCommands:\n"
            "/help\n"
            "/rooms\n"
            "/users\n"
            "/create <room> [password]\n"
            "/join <room> [password]\n"
            "/pub <username>\n"
            "/dm <username> <message>\n"
            "/quit\n"
            "Any other input sends a message to current room.\n"
        )

    def ensure_session_key(self, peer: str) -> bool:
        if peer in self.session_keys:
            return True
        pub = self.peer_pubkeys.get(peer)
        if not pub:
            self.safe_print(f"No known public key for {peer}. Use /pub {peer} first.")
            return False
        if not valid_public_key(pub):
            self.safe_print(f"[SECURITY] Rejected public key for {peer}: invalid format.")
            return False
        key = secrets.token_bytes(16)
        enc_key = rsa_encrypt(pub, key)
        msg_id, timestamp = self._make_msg_meta()
        payload = f"KEYX:{self.username}:{peer}:{msg_id}:{timestamp}:".encode("utf-8") + enc_key
        sig = rsa_sign(self.privkey, payload)
        json_send(
            self.sock,
            {
                "type": "e2ee_key",
                "to": peer,
                "msg_id": msg_id,
                "timestamp": timestamp,
                "enc_key": b64e(enc_key),
                "signature": b64e(sig),
            },
        )
        self.session_keys[peer] = key
        self.safe_print(f"E2EE session key established (sent) with {peer}.")
        return True

    def send_dm(self, peer: str, message: str) -> None:
        if not self.ensure_session_key(peer):
            return
        key = self.session_keys[peer]
        iv, cipher = tea_encrypt_cbc(key, message.encode("utf-8"))
        msg_id, timestamp = self._make_msg_meta()
        signed_payload = f"DM:{self.username}:{peer}:{msg_id}:{timestamp}:".encode("utf-8") + iv + cipher
        sig = rsa_sign(self.privkey, signed_payload)
        json_send(
            self.sock,
            {
                "type": "e2ee_dm",
                "to": peer,
                "msg_id": msg_id,
                "timestamp": timestamp,
                "iv": b64e(iv),
                "ciphertext": b64e(cipher),
                "signature": b64e(sig),
            },
        )
        peer_color = deterministic_color(peer)
        self.safe_print(
            f"{COLOR_DM_TAG}[DM]{COLOR_RESET} "
            f"{self.my_color}{self.username}{COLOR_RESET} -> "
            f"{peer_color}{peer}{COLOR_RESET}: (encrypted and signed)"
        )

    def handle_incoming(self) -> None:
        while not self.stop_event.is_set():
            try:
                frame = json_recv(self.buffer, self.sock)
            except (ConnectionError, OSError, json.JSONDecodeError):
                break
            if frame is None:
                break
            typ = frame.get("type")

            if typ == "room_message":
                ts = frame.get("timestamp", "")
                user = frame.get("from", "")
                color = frame.get("color", "")
                txt = frame.get("text", "")
                room = frame.get("room", "")
                room_label = self.format_room_name(str(room))
                self.safe_print(f"[{ts}] ({room_label}) {color}{user}{COLOR_RESET}: {txt}")

            elif typ == "room_joined":
                self.current_room = frame.get("room", self.current_room)
                if "protected" in frame:
                    self.room_protection[self.current_room] = bool(frame.get("protected"))
                self.safe_print(f"Switched to room: {self.format_room_name(self.current_room)}")

            elif typ == "rooms":
                self.print_rooms(frame.get("rooms", []))

            elif typ == "users":
                users = frame.get("users", [])
                self.safe_print("Connected users: " + ", ".join(users))

            elif typ == "pubkey":
                username = frame.get("username")
                pub = frame.get("public_key")
                if username and pub and valid_public_key(pub):
                    self.remember_peer_key(username, pub)
                    self.safe_print(f"Stored public key for {username}: n={str(pub.get('n'))[:24]}..., e={pub.get('e')}")
                elif username:
                    self.safe_print(f"[SECURITY] Rejected public key for {username}: invalid format.")

            elif typ == "user_event":
                event = frame.get("event")
                username = frame.get("username")
                if event == "joined":
                    pub = frame.get("public_key")
                    if username and pub and valid_public_key(pub):
                        self.remember_peer_key(username, pub)
                    elif username and pub:
                        self.safe_print(f"[SECURITY] Ignored invalid public key announced for {username}.")
                    self.safe_print(f"* {username} joined")
                elif event == "left":
                    self.safe_print(f"* {username} left")

            elif typ == "e2ee_key":
                sender = frame.get("from")
                to_user = frame.get("to")
                if to_user != self.username:
                    continue
                msg_id = str(frame.get("msg_id", ""))
                try:
                    timestamp = int(frame.get("timestamp", 0))
                except (TypeError, ValueError):
                    self.safe_print(f"[SECURITY] Rejected key exchange from {sender}: invalid timestamp.")
                    continue
                if not self._validate_and_track_msg(str(sender), msg_id, timestamp):
                    self.safe_print(f"[SECURITY] Rejected key exchange from {sender}: replay/freshness check failed.")
                    continue
                enc_key = safe_b64d(str(frame.get("enc_key", "")))
                sig = safe_b64d(str(frame.get("signature", "")))
                if enc_key is None or sig is None:
                    self.safe_print(f"[SECURITY] Rejected key exchange from {sender}: invalid base64 fields.")
                    continue
                pub = self.peer_pubkeys.get(sender)
                if not pub:
                    self.safe_print(f"Cannot verify key exchange from {sender}: missing public key.")
                    continue
                if not valid_public_key(pub):
                    self.safe_print(f"[SECURITY] Rejected key exchange from {sender}: invalid public key format.")
                    continue
                signed_payload = f"KEYX:{sender}:{self.username}:{msg_id}:{timestamp}:".encode("utf-8") + enc_key
                if not rsa_verify(pub, signed_payload, sig):
                    self.safe_print(f"[SECURITY] Rejected key exchange from {sender}: invalid signature.")
                    continue
                raw = rsa_decrypt(self.privkey, enc_key)
                if len(raw) < 16:
                    self.safe_print(f"[SECURITY] Rejected key exchange from {sender}: invalid key size.")
                    continue
                key = raw[-16:]
                self.session_keys[sender] = key
                self.safe_print(f"E2EE session key established with {sender}.")

            elif typ == "e2ee_dm":
                sender = frame.get("from")
                to_user = frame.get("to")
                if to_user != self.username:
                    continue
                msg_id = str(frame.get("msg_id", ""))
                try:
                    timestamp = int(frame.get("timestamp", 0))
                except (TypeError, ValueError):
                    self.safe_print(f"[SECURITY] Rejected DM from {sender}: invalid timestamp.")
                    continue
                if not self._validate_and_track_msg(str(sender), msg_id, timestamp):
                    self.safe_print(f"[SECURITY] Rejected DM from {sender}: replay/freshness check failed.")
                    continue
                key = self.session_keys.get(sender)
                if not key:
                    self.safe_print(f"[SECURITY] Rejected DM from {sender}: no session key.")
                    continue
                iv = safe_b64d(str(frame.get("iv", "")))
                cipher = safe_b64d(str(frame.get("ciphertext", "")))
                sig = safe_b64d(str(frame.get("signature", "")))
                if iv is None or cipher is None or sig is None:
                    self.safe_print(f"[SECURITY] Rejected DM from {sender}: invalid base64 fields.")
                    continue
                if len(iv) != 8:
                    self.safe_print(f"[SECURITY] Rejected DM from {sender}: invalid IV size.")
                    continue
                if len(cipher) == 0 or (len(cipher) % 8) != 0:
                    self.safe_print(f"[SECURITY] Rejected DM from {sender}: invalid ciphertext size.")
                    continue
                pub = self.peer_pubkeys.get(sender)
                if not pub:
                    self.safe_print(f"[SECURITY] Rejected DM from {sender}: missing public key.")
                    continue
                if not valid_public_key(pub):
                    self.safe_print(f"[SECURITY] Rejected DM from {sender}: invalid public key format.")
                    continue
                signed_payload = f"DM:{sender}:{self.username}:{msg_id}:{timestamp}:".encode("utf-8") + iv + cipher
                if not rsa_verify(pub, signed_payload, sig):
                    self.safe_print(f"[SECURITY] Rejected DM from {sender}: invalid signature.")
                    continue
                try:
                    plaintext = tea_decrypt_cbc(key, iv, cipher).decode("utf-8")
                except Exception:
                    self.safe_print(f"[SECURITY] Rejected DM from {sender}: decryption failed.")
                    continue
                ts = frame.get("timestamp", "")
                sender_name = str(sender)
                sender_color = deterministic_color(sender_name)
                self.safe_print(
                    f"[{ts}] {COLOR_DM_TAG}[DM]{COLOR_RESET} "
                    f"{sender_color}{sender_name}{COLOR_RESET} -> "
                    f"{self.my_color}{self.username}{COLOR_RESET}: {plaintext}"
                )

            elif typ == "info":
                self.safe_print(frame.get("message", ""))

            elif typ == "error":
                self.safe_print(f"[ERROR] {frame.get('message', 'unknown error')}")

            else:
                self.safe_print(f"[DEBUG] {frame}")

        self.safe_print("Disconnected from server.")
        self.stop_event.set()

    def run(self) -> None:
        self.connect()
        self.show_help()
        t = threading.Thread(target=self.handle_incoming, daemon=True)
        t.start()
        while not self.stop_event.is_set():
            try:
                line = input()
            except EOFError:
                line = "/quit"
            line = line.strip()
            if not line:
                continue
            if line == "/help":
                self.show_help()
                continue
            if line == "/rooms":
                json_send(self.sock, {"type": "list_rooms"})
                continue
            if line == "/users":
                json_send(self.sock, {"type": "list_users"})
                continue
            if line.startswith("/create "):
                parts = line.split(" ", 2)
                if len(parts) < 2:
                    self.safe_print("Usage: /create <room> [password]")
                    continue
                room = parts[1].strip()
                password = parts[2].strip() if len(parts) == 3 else None
                json_send(self.sock, {"type": "create_room", "room": room, "password": password})
                continue
            if line.startswith("/join "):
                parts = line.split(" ", 2)
                if len(parts) < 2:
                    self.safe_print("Usage: /join <room> [password]")
                    continue
                room = parts[1].strip()
                password = parts[2].strip() if len(parts) == 3 else None
                json_send(self.sock, {"type": "join_room", "room": room, "password": password})
                continue
            if line.startswith("/pub "):
                target = line.split(" ", 1)[1].strip()
                if not target:
                    self.safe_print("Usage: /pub <username>")
                    continue
                json_send(self.sock, {"type": "get_pubkey", "username": target})
                continue
            if line.startswith("/dm "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    self.safe_print("Usage: /dm <username> <message>")
                    continue
                self.send_dm(parts[1].strip(), parts[2])
                continue
            if line == "/quit":
                json_send(self.sock, {"type": "quit"})
                self.stop_event.set()
                break
            json_send(self.sock, {"type": "room_chat", "text": line})

        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Crypto Vibeness chat client")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    client = ChatClient(args.host, args.port)
    client.run()


if __name__ == "__main__":
    main()
