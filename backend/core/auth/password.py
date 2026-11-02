"""Password hashing with bcrypt.

Uses the ``bcrypt`` package directly instead of passlib: passlib 1.7.4 probes the
backend with a >72-byte secret and raises on bcrypt >= 4.1, which made every
login fail with "password cannot be longer than 72 bytes" after a routine
dependency bump. The stored hashes are unchanged ($2b$...), so existing accounts
keep working.
"""
from typing import Optional

import bcrypt

_BCRYPT_MAX_BYTES = 72


def _prepare(password: str) -> bytes:
    # bcrypt ignores everything past 72 bytes; truncate explicitly so both
    # hashing and verification agree and the library never raises.
    return (password or "").encode("utf-8")[:_BCRYPT_MAX_BYTES]


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(_prepare(plain_password), hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(_prepare(password), bcrypt.gensalt()).decode("utf-8")


def password_problem(password: str, username: str = "", min_length: int = 10) -> Optional[str]:
    """Return a human readable reason when a new password is unacceptable."""
    if not password or not password.strip():
        return "密码不能为空"
    if len(password) < min_length:
        return f"密码长度至少 {min_length} 位"
    if len(password.encode("utf-8")) > _BCRYPT_MAX_BYTES:
        return "密码过长（bcrypt 上限 72 字节）"
    if password.strip().lower() == (username or "").strip().lower():
        return "密码不能与用户名相同"
    if password.lower() in {"12345678", "123456789", "password", "admin123", "qwertyui", "11111111"}:
        return "密码过于常见，请换一个"
    return None
