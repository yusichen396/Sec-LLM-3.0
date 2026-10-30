"""Sec-LLM Agent Platform Configuration."""
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    # Base
    ENV_MODE: str = "dev"
    JWT_SECRET_KEY: str = "default-unsafe-secret-key"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    INITIAL_ADMIN_PASSWORD: Optional[str] = None

    # LLM core
    LLM_PROVIDER: str = "local"  # local or cloud

    # Cloud DeepSeek
    DEEPSEEK_API_KEY: Optional[str] = None
    DEEPSEEK_BASE_URL: str = "https://api.deepseek.com"
    DEEPSEEK_MODEL_NAME: str = "deepseek-chat"
    ABUSEIPDB_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    THREAT_INTEL_TIMEOUT_SECONDS: float = 4.0

    # Local Ollama
    OLLAMA_BASE_URL: str = "http://127.0.0.1:11434"
    OLLAMA_MODEL_NAME: str = "llama3:8b"
    RAG_ONLY_MAX_DISTANCE: float = 1.2
    # 安全护栏：话题域识别 + 越权拦截，关闭后 /api/chat 不再做前置检查
    SAFETY_GUARD_ENABLED: bool = True
    # 混合召回：BM25 + 向量 RRF 融合；集合超过 5000 条时自动退化为纯向量
    HYBRID_RECALL_ENABLED: bool = True
    # Optional profile path; empty uses data/rag_optimization/active.json when present.
    RAG_POLICY_PATH: Optional[str] = None

    # Database
    DATABASE_TYPE: str = "mysql"
    MYSQL_USER: str = "root"
    MYSQL_PASSWORD: str = ""
    MYSQL_HOST: str = "localhost"
    MYSQL_PORT: int = 3306
    MYSQL_DB: str = "sec_llm_db"

    # Mail (optional)
    MAIL_USERNAME: Optional[str] = None
    MAIL_PASSWORD: Optional[str] = None
    MAIL_FROM: Optional[str] = None
    MAIL_PORT: int = 587
    MAIL_SERVER: Optional[str] = None
    MAIL_FROM_NAME: str = "Sec-LLM Security Team"
    DOMAIN_URL: str = "http://localhost:3000"

    # OpenClaw Skill API Key (optional)
    SEC_LLM_SKILL_API_KEY: Optional[str] = None

    # Agent platform settings (NEW)
    AGENT_SANDBOX_IMAGE: str = "sec-llm-sandbox:latest"
    AGENT_MAX_STEPS: int = 20
    AGENT_STEP_TIMEOUT_SECONDS: int = 300
    AGENT_TASK_TIMEOUT_SECONDS: int = 1800
    AGENT_MAX_CONCURRENT: int = 4
    AGENT_BROWSER_HEADLESS: bool = True
    AGENT_DEFAULT_SCAN_MODE: str = "standard"  # standard | deep | quick
    AGENT_ALLOWED_TARGETS: str = ""  # comma-separated exact hostnames/IPs; required for production web scans
    AGENT_POLICY_PATH: Optional[str] = None  # default: data/agent_optimization/active.json
    RERANKER_MODEL_PATH: Optional[str] = None

settings = Settings()


def normalize_provider(provider: Optional[str]) -> str:
    p = (provider or "").strip().lower()
    if p not in {"local", "cloud"}:
        if p:
            import logging
            logging.warning(f"Unknown LLM provider '{provider}', falling back to 'local'")
        return "local"
    return p


def get_user_provider(current_user: Optional[dict]) -> str:
    if current_user and current_user.get("llm_provider"):
        return normalize_provider(current_user.get("llm_provider"))
    return normalize_provider(settings.LLM_PROVIDER)
