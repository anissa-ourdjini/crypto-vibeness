#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from common import (
    COLOR_PALETTE,
    COLOR_RESET,
    DEFAULT_HOST,
    DEFAULT_PORT,
    b64d,
    b64e,
    deterministic_color,
    json_recv,
    json_send,
    safe_b64d,
    valid_public_key,
)
from security_utils import (
    anonymize_ip,
    hash_password_record,
    password_entropy_bits,
    password_strength_level,
    validate_password,
    valid_msg_id,
    valid_timestamp,
    verify_password_record,
)

# Server defaults and file paths.
DEFAULT_ROOM = "general"

CREDENTIALS_FILE = Path("this_is_safe.txt")
PASSWORD_RULES_FILE = Path("password_rules.json")
LOG_FILE_TEMPLATE = "log_{timestamp}.txt"

AUTH_WINDOW_SECONDS = 300
AUTH_MAX_ATTEMPTS = 5
AUTH_LOCKOUT_BASE_SECONDS = 10
AUTH_LOCKOUT_MAX_SECONDS = 300

def now_str() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_password_rules() -> dict:
    if not PASSWORD_RULES_FILE.exists():
        return {
            "min_length": 10,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digit": True,
            "require_symbol": True,
        }
    with PASSWORD_RULES_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_credentials() -> Dict[str, str]:
    creds: Dict[str, str] = {}
    if not CREDENTIALS_FILE.exists():
        return creds
    with CREDENTIALS_FILE.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or ":" not in line:
                continue
            username, rest = line.split(":", 1)
            creds[username] = rest
    return creds


def secure_credentials_file_permissions() -> None:
    if not CREDENTIALS_FILE.exists():
        return
    try:
        os.chmod(CREDENTIALS_FILE, 0o600)
    except OSError:
        # On some Windows setups chmod may be a no-op or restricted.
        pass


def save_credentials(creds: Dict[str, str]) -> None:
    with CREDENTIALS_FILE.open("w", encoding="utf-8") as f:
        for user in sorted(creds):
            f.write(f"{user}:{creds[user]}\n")
    secure_credentials_file_permissions()


@dataclass
class Room:
    name: str
    password: Optional[str] = None
    members: Set[str] = field(default_factory=set)

    @property
    def protected(self) -> bool:
        return self.password is not None


@dataclass
class ClientSession:
    conn: socket.socket
    addr: Tuple[str, int]
    username: str
    color: str
    current_room: str = DEFAULT_ROOM
    public_key: Optional[dict] = None
    buffer: bytearray = field(default_factory=bytearray)


class ChatServer:
    def __init__(self, host: str, port: int, tamper_next_dm: bool = False) -> None:
        self.host = host
        self.port = port
        self.lock = threading.RLock()
        self.creds = load_credentials()
        secure_credentials_file_permissions()
        self.rooms: Dict[str, Room] = {DEFAULT_ROOM: Room(DEFAULT_ROOM)}
        self.clients: Dict[str, ClientSession] = {}
        self.pubkeys: Dict[str, dict] = {}
        timestamp = dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.log_file = Path(LOG_FILE_TEMPLATE.format(timestamp=timestamp))
        self.log_lock = threading.Lock()
        self.server_sock: Optional[socket.socket] = None
        self.failed_auth_by_user: Dict[str, list] = {}
        self.failed_auth_by_ip: Dict[str, list] = {}
        self.user_lockout_until: Dict[str, float] = {}
        self.ip_lockout_until: Dict[str, float] = {}
        self.tamper_next_dm = tamper_next_dm

    def log(self, msg: str) -> None:
        line = f"[{now_str()}] {msg}"
        print(line)
        with self.log_lock:
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def room_list_payload(self) -> list:
        payload = []
        for room in sorted(self.rooms.values(), key=lambda r: r.name):
            payload.append(
                {
                    "name": room.name,
                    "protected": room.protected,
                    "members": len(room.members),
                }
            )
        return payload

    def assign_unique_color(self, username: str) -> str:
        used_colors = {client.color for client in self.clients.values() if client.username != username}
        for color in COLOR_PALETTE:
            if color not in used_colors:
                return color
        # Palette exhausted: fall back to deterministic mapping.
        return deterministic_color(username)

    def send_to_user(self, username: str, payload: dict) -> None:
        client = self.clients.get(username)
        if client:
            json_send(client.conn, payload)

    def broadcast_room(self, room_name: str, payload: dict, exclude: Optional[str] = None) -> None:
        room = self.rooms.get(room_name)
        if not room:
            return
        for user in list(room.members):
            if exclude and user == exclude:
                continue
            self.send_to_user(user, payload)

    def remove_client(self, username: str) -> None:
        with self.lock:
            client = self.clients.pop(username, None)
            self.pubkeys.pop(username, None)
            for room in self.rooms.values():
                room.members.discard(username)
            if not client:
                return
            try:
                client.conn.close()
            except OSError:
                pass
        self.log(f"{username} disconnected")
        for other in list(self.clients):
            self.send_to_user(other, {"type": "user_event", "event": "left", "username": username})

    def maybe_tamper_dm_ciphertext(self, ciphertext_b64: object) -> object:
        if not isinstance(ciphertext_b64, str):
            return ciphertext_b64
        ciphertext = safe_b64d(ciphertext_b64)
        if not ciphertext:
            return ciphertext_b64
        flipped = bytearray(ciphertext)
        # Flip the last byte so that, even without signature checks, CBC padding is very likely invalid.
        idx = len(flipped) - 1
        flipped[idx] ^= 0x01
        return b64e(bytes(flipped))

    def _prune_failures(self, failures: Dict[str, list], now_ts: float) -> None:
        cutoff = now_ts - AUTH_WINDOW_SECONDS
        for key, values in list(failures.items()):
            kept = [ts for ts in values if ts >= cutoff]
            if kept:
                failures[key] = kept
            else:
                failures.pop(key, None)

    def _is_auth_locked(self, username: str, ip_addr: str, now_ts: float) -> bool:
        return (self.user_lockout_until.get(username, 0.0) > now_ts) or (self.ip_lockout_until.get(ip_addr, 0.0) > now_ts)

    def _register_auth_failure(self, username: str, ip_addr: str, now_ts: float) -> None:
        user_failures = self.failed_auth_by_user.setdefault(username, [])
        ip_failures = self.failed_auth_by_ip.setdefault(ip_addr, [])
        user_failures.append(now_ts)
        ip_failures.append(now_ts)

        self._prune_failures(self.failed_auth_by_user, now_ts)
        self._prune_failures(self.failed_auth_by_ip, now_ts)

        user_count = len(self.failed_auth_by_user.get(username, []))
        ip_count = len(self.failed_auth_by_ip.get(ip_addr, []))
        pressure = max(user_count, ip_count)
        if pressure >= AUTH_MAX_ATTEMPTS:
            exponent = pressure - AUTH_MAX_ATTEMPTS
            delay = min(AUTH_LOCKOUT_BASE_SECONDS * (2**exponent), AUTH_LOCKOUT_MAX_SECONDS)
            lock_until = now_ts + delay
            self.user_lockout_until[username] = max(self.user_lockout_until.get(username, 0.0), lock_until)
            self.ip_lockout_until[ip_addr] = max(self.ip_lockout_until.get(ip_addr, 0.0), lock_until)

    def _register_auth_success(self, username: str, ip_addr: str) -> None:
        self.failed_auth_by_user.pop(username, None)
        self.failed_auth_by_ip.pop(ip_addr, None)
        self.user_lockout_until.pop(username, None)
        self.ip_lockout_until.pop(ip_addr, None)

    def auth_handshake(
        self, conn: socket.socket, buffer: bytearray, username: str, ip_addr: str
    ) -> Tuple[bool, Optional[str], Optional[dict]]:
        if username in self.clients:
            json_send(conn, {"type": "error", "message": "Username already connected"})
            return False, None, None

        with self.lock:
            now_ts = time.time()
            self._prune_failures(self.failed_auth_by_user, now_ts)
            self._prune_failures(self.failed_auth_by_ip, now_ts)
            if self._is_auth_locked(username, ip_addr, now_ts):
                json_send(conn, {"type": "error", "message": "Invalid credentials or temporarily locked"})
                return False, None, None

        rules = load_password_rules()
        existing = username in self.creds
        json_send(
            conn,
            {
                "type": "auth_challenge",
                "existing": existing,
                "rules": rules,
            },
        )
        submit = json_recv(buffer, conn)
        if not submit or submit.get("type") != "auth_submit":
            json_send(conn, {"type": "error", "message": "Authentication protocol error"})
            return False, None, None
        password = str(submit.get("password", ""))
        if not password:
            json_send(conn, {"type": "error", "message": "Password is required"})
            return False, None, None

        with self.lock:
            now_ts = time.time()
            if username in self.creds:
                if not verify_password_record(self.creds[username], password):
                    self._register_auth_failure(username, ip_addr, now_ts)
                    json_send(conn, {"type": "error", "message": "Invalid credentials or temporarily locked"})
                    return False, None, None
                if self.creds[username].count(":") == 0:
                    # Legacy md5 account, transparently upgrade on successful login.
                    self.creds[username] = hash_password_record(password)
                    save_credentials(self.creds)
            else:
                ok, reason = validate_password(password, rules)
                if not ok:
                    self._register_auth_failure(username, ip_addr, now_ts)
                    json_send(conn, {"type": "error", "message": "Invalid credentials or temporarily locked"})
                    return False, None, None
                self.creds[username] = hash_password_record(password)
                save_credentials(self.creds)
                entropy_bits = round(password_entropy_bits(password), 2)
                json_send(
                    conn,
                    {
                        "type": "password_strength",
                        "entropy_bits": entropy_bits,
                        "strength_level": password_strength_level(entropy_bits),
                    },
                )
            self._register_auth_success(username, ip_addr)
        return True, password, rules

    def join_room(self, username: str, room_name: str) -> None:
        client = self.clients[username]
        old_room = self.rooms.get(client.current_room)
        if old_room:
            old_room.members.discard(username)
        room = self.rooms[room_name]
        room.members.add(username)
        client.current_room = room_name

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        buffer = bytearray()
        username = None
        try:
            hello = json_recv(buffer, conn)
            if not hello or hello.get("type") != "hello":
                json_send(conn, {"type": "error", "message": "Expected hello frame"})
                conn.close()
                return

            username = str(hello.get("username", "")).strip()
            if not username or ":" in username or " " in username:
                json_send(conn, {"type": "error", "message": "Invalid username"})
                conn.close()
                return
            public_key = hello.get("public_key")
            if not valid_public_key(public_key):
                json_send(conn, {"type": "error", "message": "Invalid public key"})
                conn.close()
                return

            ok, _, _ = self.auth_handshake(conn, buffer, username, addr[0])
            if not ok:
                conn.close()
                return

            with self.lock:
                color = self.assign_unique_color(username)
                session = ClientSession(conn=conn, addr=addr, username=username, color=color, public_key=public_key)
                self.clients[username] = session
                self.pubkeys[username] = public_key
                self.rooms[DEFAULT_ROOM].members.add(username)

                directory = {u: pk for u, pk in self.pubkeys.items() if u != username and pk}

            json_send(
                conn,
                {
                    "type": "auth_ok",
                    "username": username,
                    "color": color,
                    "current_room": DEFAULT_ROOM,
                    "rooms": self.room_list_payload(),
                    "public_directory": directory,
                },
            )
            self.log(f"{username} connected from {anonymize_ip(addr[0])}")

            for other in list(self.clients):
                if other != username:
                    self.send_to_user(other, {"type": "user_event", "event": "joined", "username": username, "public_key": public_key})

            while True:
                frame = json_recv(buffer, conn)
                if frame is None:
                    break
                frame_type = frame.get("type")

                if frame_type == "create_room":
                    room_name = str(frame.get("room", "")).strip()
                    password = frame.get("password")
                    if not room_name:
                        json_send(conn, {"type": "error", "message": "Room name required"})
                        continue
                    with self.lock:
                        if room_name in self.rooms:
                            json_send(conn, {"type": "error", "message": "Room already exists"})
                            continue
                        self.rooms[room_name] = Room(room_name, str(password) if password else None)
                    self.log(f"{username} created room {room_name} (protected={bool(password)})")
                    json_send(conn, {"type": "info", "message": f"Room {room_name} created"})

                elif frame_type == "join_room":
                    room_name = str(frame.get("room", "")).strip()
                    provided = frame.get("password")
                    with self.lock:
                        room = self.rooms.get(room_name)
                        if not room:
                            json_send(conn, {"type": "error", "message": "Room does not exist"})
                            continue
                        if room.protected and room.password != str(provided):
                            json_send(conn, {"type": "error", "message": "Wrong room password"})
                            continue
                        self.join_room(username, room_name)
                        protected = room.protected
                    self.log(f"{username} joined room {room_name}")
                    json_send(conn, {"type": "room_joined", "room": room_name, "protected": protected})

                elif frame_type == "list_rooms":
                    json_send(conn, {"type": "rooms", "rooms": self.room_list_payload()})

                elif frame_type == "list_users":
                    json_send(conn, {"type": "users", "users": sorted(self.clients)})

                elif frame_type == "get_pubkey":
                    requested = str(frame.get("username", "")).strip()
                    with self.lock:
                        key = self.pubkeys.get(requested)
                    if not key:
                        json_send(conn, {"type": "error", "message": f"No public key for {requested}"})
                        continue
                    json_send(conn, {"type": "pubkey", "username": requested, "public_key": key})

                elif frame_type == "room_chat":
                    text = str(frame.get("text", "")).rstrip()
                    if not text:
                        continue
                    with self.lock:
                        current_room = self.clients[username].current_room
                        color = self.clients[username].color
                    payload = {
                        "type": "room_message",
                        "room": current_room,
                        "from": username,
                        "color": color,
                        "timestamp": now_str(),
                        "text": text,
                    }
                    self.broadcast_room(current_room, payload)
                    self.log(f"room_chat room={current_room} from={username} chars={len(text)}")

                elif frame_type == "e2ee_key":
                    to_user = str(frame.get("to", "")).strip()
                    if to_user not in self.clients:
                        json_send(conn, {"type": "error", "message": f"{to_user} is not connected"})
                        continue
                    if not valid_msg_id(frame.get("msg_id")):
                        json_send(conn, {"type": "error", "message": "Invalid msg_id"})
                        continue
                    if not valid_timestamp(frame.get("timestamp")):
                        json_send(conn, {"type": "error", "message": "Invalid timestamp"})
                        continue
                    enc_key = safe_b64d(str(frame.get("enc_key", "")))
                    sig = safe_b64d(str(frame.get("signature", "")))
                    if enc_key is None or sig is None:
                        json_send(conn, {"type": "error", "message": "Invalid base64 payload"})
                        continue
                    relay = {
                        "type": "e2ee_key",
                        "from": username,
                        "to": to_user,
                        "msg_id": frame.get("msg_id"),
                        "timestamp": frame.get("timestamp"),
                        "enc_key": frame.get("enc_key"),
                        "signature": frame.get("signature"),
                    }
                    self.send_to_user(to_user, relay)
                    enc_preview = str(frame.get("enc_key", ""))[:48]
                    self.log(
                        f"e2ee_key from={username} to={to_user} keyblob_bytes={len(enc_key)} "
                        f"enc_key_b64_preview={enc_preview}..."
                    )

                elif frame_type == "e2ee_dm":
                    to_user = str(frame.get("to", "")).strip()
                    if to_user not in self.clients:
                        json_send(conn, {"type": "error", "message": f"{to_user} is not connected"})
                        continue
                    if not valid_msg_id(frame.get("msg_id")):
                        json_send(conn, {"type": "error", "message": "Invalid msg_id"})
                        continue
                    if not valid_timestamp(frame.get("timestamp")):
                        json_send(conn, {"type": "error", "message": "Invalid timestamp"})
                        continue
                    iv = safe_b64d(str(frame.get("iv", "")))
                    ciphertext = safe_b64d(str(frame.get("ciphertext", "")))
                    sig = safe_b64d(str(frame.get("signature", "")))
                    if iv is None or ciphertext is None or sig is None:
                        json_send(conn, {"type": "error", "message": "Invalid base64 payload"})
                        continue
                    if len(iv) != 8:
                        json_send(conn, {"type": "error", "message": "Invalid IV size"})
                        continue
                    if len(ciphertext) == 0 or (len(ciphertext) % 8) != 0:
                        json_send(conn, {"type": "error", "message": "Invalid ciphertext size"})
                        continue
                    relay_ciphertext = frame.get("ciphertext")
                    with self.lock:
                        if self.tamper_next_dm:
                            relay_ciphertext = self.maybe_tamper_dm_ciphertext(relay_ciphertext)
                            self.log(
                                f"[LAB] tampered 1 byte in e2ee_dm ciphertext from={username} to={to_user}; "
                                "recipient must reject signature"
                            )
                    relay = {
                        "type": "e2ee_dm",
                        "from": username,
                        "to": to_user,
                        "msg_id": frame.get("msg_id"),
                        "timestamp": frame.get("timestamp"),
                        "iv": frame.get("iv"),
                        "ciphertext": relay_ciphertext,
                        "signature": frame.get("signature"),
                        "server_timestamp": now_str(),
                    }
                    self.send_to_user(to_user, relay)
                    iv_preview = str(frame.get("iv", ""))[:16]
                    cipher_preview = str(frame.get("ciphertext", ""))[:48]
                    self.log(
                        f"e2ee_dm from={username} to={to_user} cipher_bytes={len(ciphertext)} "
                        f"iv_b64={iv_preview}... ciphertext_b64_preview={cipher_preview}..."
                    )

                elif frame_type == "quit":
                    break

                else:
                    json_send(conn, {"type": "error", "message": f"Unknown frame type: {frame_type}"})
        except (ConnectionError, OSError, json.JSONDecodeError):
            pass
        finally:
            if username:
                self.remove_client(username)
            else:
                try:
                    conn.close()
                except OSError:
                    pass

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen()
        self.server_sock = sock
        self.log(f"Server listening on {self.host}:{self.port}")
        if self.tamper_next_dm:
            self.log("[LAB] Tamper mode enabled: every relayed e2ee_dm will be altered by 1 byte.")
        try:
            while True:
                conn, addr = sock.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            self.log("Server interrupted, shutting down")
        finally:
            sock.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Crypto Vibeness chat server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--tamper-next-dm",
        action="store_true",
        help="Lab mode: alter one byte in every relayed e2ee_dm ciphertext (for signature rejection demo).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = ChatServer(args.host, args.port, tamper_next_dm=args.tamper_next_dm)
    server.run()


if __name__ == "__main__":
    main()
