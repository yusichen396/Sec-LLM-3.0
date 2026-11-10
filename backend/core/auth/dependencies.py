"""FastAPI auth dependencies: dual JWT + Skill API Key authentication."""
import secrets
from typing import Any, Dict, Optional

import pymysql
from fastapi import Depends, HTTPException, Request, status

from config import settings
from core.auth.jwt import get_current_user, oauth2_scheme


def get_db_connection():
    return pymysql.connect(
        host=settings.MYSQL_HOST,
        user=settings.MYSQL_USER,
        password=settings.MYSQL_PASSWORD,
        database=settings.MYSQL_DB,
        port=settings.MYSQL_PORT,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def get_db():
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()


async def get_current_active_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db=Depends(get_db),
) -> Dict[str, Any]:
    """Resolve the JWT user and require an active account.

    ``db`` must be injected here: ``core.auth.jwt.get_current_user`` declares
    ``db=None`` and returns None when it is not passed, so depending on that
    function directly made every endpoint below ``get_current_active_user``
    answer 401 for valid tokens.
    """
    current_user = await get_current_user(token, db)
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated or token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


async def get_current_user_or_skill(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db=Depends(get_db),
) -> Dict[str, Any]:
    """Support JWT or OpenClaw Skill API Key. Skill Key maps to admin user."""
    skill_key = request.headers.get("X-Skill-Api-Key")
    if (
        settings.SEC_LLM_SKILL_API_KEY
        and skill_key
        and secrets.compare_digest(skill_key, settings.SEC_LLM_SKILL_API_KEY)
    ):
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username=%s", ("admin",))
            admin_user = cursor.fetchone()
        if admin_user and admin_user.get("is_active"):
            print(f"[AUTH] Skill API Key authenticated as admin (user_id={admin_user['id']})")
            return admin_user
        elif not admin_user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Skill API Key configured but admin account does not exist",
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin account is disabled")
    user = await get_current_user(token, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated, token expired, or invalid Skill API Key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_admin_user(
    current_user: Dict[str, Any] = Depends(get_current_active_user),
) -> Dict[str, Any]:
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user
