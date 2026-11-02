"""Tests for the auth module."""
import inspect

import pytest
from core.auth.password import verify_password, get_password_hash, password_needs_rehash
from core.auth.dependencies import get_current_active_user
from core.auth.jwt import create_access_token, get_current_user


class TestPasswordHashing:
    def test_hash_and_verify(self):
        pw = "test-password-123"
        hashed = get_password_hash(pw)
        assert hashed != pw
        assert verify_password(pw, hashed)
        assert not verify_password("wrong-password", hashed)
        assert not password_needs_rehash(hashed)

    def test_legacy_passlib_hash_still_verifies(self):
        """升级前用 passlib 写入的 $pbkdf2$ 哈希必须继续可用，否则老账号全被锁死。"""
        passlib = pytest.importorskip("passlib.context")
        legacy = passlib.CryptContext(schemes=["pbkdf2_sha256"]).hash("admin123")
        assert verify_password("admin123", legacy)
        assert not verify_password("wrong", legacy)
        assert password_needs_rehash(legacy)

    def test_access_token_dependency_injects_db(self):
        """get_current_active_user 必须自己注入 db；否则所有依赖它的端点恒 401。"""
        params = inspect.signature(get_current_active_user).parameters
        assert "db" in params
        assert params["db"].default is not inspect.Parameter.empty
        assert "token" in params

    def test_different_hashes(self):
        h1 = get_password_hash("pw1")
        h2 = get_password_hash("pw1")
        assert h1 != h2
        assert verify_password("pw1", h1)
        assert verify_password("pw1", h2)


class TestJwt:
    def test_create_token(self):
        token = create_access_token({"sub": "testuser"})
        assert token is not None
        assert len(token) > 50

    def test_token_with_expiry(self):
        from datetime import timedelta
        token = create_access_token({"sub": "testuser"}, expires_delta=timedelta(hours=1))
        assert token is not None

    def test_disabled_user_token_is_rejected(self):
        import asyncio

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def execute(self, *_):
                pass

            def fetchone(self):
                return {"username": "disabled", "is_active": False}

        class DB:
            def cursor(self):
                return Cursor()

        token = create_access_token({"sub": "disabled"})
        assert asyncio.run(get_current_user(token, DB())) is None
