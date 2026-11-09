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
    # Comma-separated exact origins; never "*" together with credentials.
    CORS_ALLOW_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"
    # Login throttling: failures per (client, username) inside the window lock the pair out.
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_FAILURE_WINDOW_SECONDS: int = 300
    # Minimum local-part length for self-service registration (admin stays at 12).
    USER_PASSWORD_MIN_LENGTH: int = 10
    # Uploads: hard cap before anything is written or parsed.
    MAX_UPLOAD_BYTES: int = 20 * 1024 * 1024
    UPLOAD_ALLOWED_EXTENSIONS: str = "pdf,txt,log,json,csv,md"
    # Chat/query text is user content; keep it out of logs unless explicitly enabled.
    LOG_USER_QUERIES: bool = False

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
    # 规划校验失败时的重试次数（0 表示不重试）
    AGENT_PLAN_RETRIES: int = 1
    # 工具执行失败的重试次数（仅对超时/连接类临时错误生效）
    AGENT_STEP_RETRIES: int = 1
    AGENT_STEP_RETRY_BACKOFF_SECONDS: float = 0.5
    # 连续多少步失败后提前终止（0 表示不熔断）
    AGENT_MAX_CONSECUTIVE_FAILURES: int = 2
    # 熔断阈值按计划长度放大：每 N 步容忍一次连续失败（0 表示只用固定下限）
    AGENT_CIRCUIT_BREAKER_RATIO: float = 3.0
    # 失败后允许的重新规划次数（0 表示不做自我修正）
    AGENT_MAX_REPLANS: int = 1
    # 目标类型与工具不匹配时，执行前拦截（需重规划）
    AGENT_ENFORCE_TARGET_TOOL_MATCH: bool = True
    AGENT_TASK_TIMEOUT_SECONDS: int = 1800
    AGENT_MAX_CONCURRENT: int = 4
    AGENT_BROWSER_HEADLESS: bool = True
    AGENT_DEFAULT_SCAN_MODE: str = "standard"  # standard | deep | quick
    AGENT_ALLOWED_TARGETS: str = ""  # comma-separated exact hostnames/IPs; required for production web scans
    # Server-side root that code_audit may read; empty disables filesystem auditing.
    AGENT_CODE_AUDIT_ROOT: str = ""
    AGENT_CODE_AUDIT_MAX_BYTES: int = 2 * 1024 * 1024
    # Optional recon port scan; skipped when Docker is unavailable.
    AGENT_RECON_PORTSCAN: bool = True
    # Browser tools refuse loopback/private/link-local targets unless explicitly allowed
    # (needed only for lab deployments that scan their own network).
    AGENT_ALLOW_PRIVATE_TARGETS: bool = False
    # Politeness: minimum gap between requests to the same origin (seconds).
    AGENT_MIN_REQUEST_INTERVAL_SECONDS: float = 1.0
    # Bounded crawl used for attack-surface discovery.
    AGENT_CRAWL_MAX_PAGES: int = 20
    AGENT_CRAWL_MAX_DEPTH: int = 2
    # Use an installed system browser instead of the bundled Chromium:
    # "msedge" / "chrome" (empty = Playwright's own download).
    AGENT_BROWSER_CHANNEL: str = ""
    # Authenticated scanning: where storage_state blobs live and how long they last.
    AGENT_SESSION_DIR: str = "data/sessions"
    AGENT_SESSION_TTL_SECONDS: int = 1800
    # Reproducible evidence artifacts (request/response + PoC) per session.
    AGENT_EVIDENCE_DIR: str = "artifacts/evidence"
    # Auto-fix PR helper stays disabled and is never exposed to the planner.
    AGENT_AUTOFIX_ENABLED: bool = False
    AGENT_POLICY_PATH: Optional[str] = None  # default: data/agent_optimization/active.json
    RERANKER_MODEL_PATH: Optional[str] = None
    PROMPT_INTENT_SEMANTIC_ENABLED: bool = True
    PROMPT_INTENT_MODEL_PATH: Optional[str] = None
    PROMPT_INTENT_ATTACK_THRESHOLD: float = 0.64
    PROMPT_INTENT_MARGIN: float = 0.04

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
