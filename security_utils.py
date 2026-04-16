import hashlib
import hmac
import math
import secrets

from common import b64d, b64e

PBKDF2_ALGO = "pbkdf2_sha256"
PBKDF2_COST = 200_000
SALT_BYTES = 16


def valid_msg_id(msg_id: object) -> bool:
    if not isinstance(msg_id, str):
        return False
    if len(msg_id) != 32:
        return False
    return all(c in "0123456789abcdef" for c in msg_id)


def valid_timestamp(value: object) -> bool:
    try:
        int(value)
    except (TypeError, ValueError):
        return False
    return True


def password_entropy_bits(password: str) -> float:
    if not password:
        return 0.0
    alphabet = 0
    if any(c.islower() for c in password):
        alphabet += 26
    if any(c.isupper() for c in password):
        alphabet += 26
    if any(c.isdigit() for c in password):
        alphabet += 10
    if any(not c.isalnum() for c in password):
        alphabet += 33
    alphabet = max(alphabet, 1)
    return len(password) * math.log2(alphabet)


def password_strength_level(entropy_bits: float) -> str:
    if entropy_bits < 40:
        return "faible"
    if entropy_bits < 60:
        return "medium"
    return "fort"


def validate_password(password: str, rules: dict) -> tuple[bool, str]:
    if len(password) < int(rules.get("min_length", 0)):
        return False, f"Password must be at least {rules.get('min_length')} chars"
    if rules.get("require_uppercase", False) and not any(c.isupper() for c in password):
        return False, "Password must include an uppercase letter"
    if rules.get("require_lowercase", False) and not any(c.islower() for c in password):
        return False, "Password must include a lowercase letter"
    if rules.get("require_digit", False) and not any(c.isdigit() for c in password):
        return False, "Password must include a digit"
    if rules.get("require_symbol", False) and not any(not c.isalnum() for c in password):
        return False, "Password must include a symbol"
    return True, "ok"


def md5_b64(password: str) -> str:
    return b64e(hashlib.md5(password.encode("utf-8")).digest())


def pbkdf2_digest(password: str, salt: bytes, cost: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, cost, dklen=32)


def hash_password_record(password: str, *, cost: int = PBKDF2_COST, salt_bytes: int = SALT_BYTES) -> str:
    salt = secrets.token_bytes(salt_bytes)
    digest = pbkdf2_digest(password, salt, cost)
    return f"{PBKDF2_ALGO}:{cost}:{b64e(salt)}:{b64e(digest)}"


def verify_password_record(record: str, provided_password: str) -> bool:
    parts = record.split(":")
    if len(parts) == 1:
        expected = parts[0]
        got = md5_b64(provided_password)
        return hmac.compare_digest(expected, got)
    if len(parts) == 4 and parts[0] == PBKDF2_ALGO:
        _, cost_s, salt_b64, digest_b64 = parts
        cost = int(cost_s)
        salt = b64d(salt_b64)
        expected = b64d(digest_b64)
        got = pbkdf2_digest(provided_password, salt, cost)
        return hmac.compare_digest(expected, got)
    return False


def anonymize_ip(ip_addr: str) -> str:
    parts = ip_addr.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.x"
    if ":" in ip_addr:
        chunks = [c for c in ip_addr.split(":") if c]
        if len(chunks) >= 2:
            return f"{chunks[0]}:{chunks[1]}:*"
        return "ipv6:*"
    return "unknown"
