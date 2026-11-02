"""Query rewriting for RAG — resolves pronouns and adds context."""
from typing import Dict, List

from config import settings, normalize_provider


async def rewrite_query(user_msg: str, history: List[Dict[str, str]], provider: str = "local"):
    """Rewrite user query using conversation history for better RAG retrieval."""
    if not history:
        return user_msg

    history_text = ""
    for msg in history[-4:]:
        role = "User" if msg.get("role") == "user" else "Assistant"
        history_text += role + ": " + (msg.get("content") or "") + "\n"

    system_prompt = (
        "You are a search query optimization expert. "
        "Rewrite the follow-up question into a standalone search query. "
        "Rules: 1. Replace pronouns with nouns. 2. Fill in context. "
        "3. Keep meaning. 4. Output ONLY the rewritten sentence."
    )
    user_prompt = "[History]: " + history_text + "\n[Question]: " + user_msg + "\n[Rewritten]:"

    selected = normalize_provider(provider)
    if selected == "cloud" and not settings.DEEPSEEK_API_KEY:
        return user_msg
    try:
        # 走统一的异步路由，避免在事件循环里调用同步 OpenAI 客户端
        from core.llm.router import single_shot_completion

        new_query = (await single_shot_completion(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            provider=selected,
            temperature=0.1,
        )).strip()
        if settings.LOG_USER_QUERIES:
            print(f"[Rewriting] {len(user_msg)} chars -> {len(new_query)} chars")
        return new_query or user_msg
    except Exception as e:
        print(f"[Rewriting Error] {type(e).__name__}")
    return user_msg


def extract_query_keywords(text: str):
    """Extract English words and Chinese characters for keyword matching."""
    import re
    if not text:
        return []
    parts = re.findall(r"[A-Za-z0-9_]+|[一-鿿]{2,}", text.lower())
    dedup = []
    seen = set()
    for p in parts:
        if len(p) >= 2 and p not in seen:
            seen.add(p)
            dedup.append(p)
    return dedup


def query_matches_context(query: str, context: str) -> bool:
    """Check if query keywords appear in the retrieved context."""
    keywords = extract_query_keywords(query)
    if not keywords:
        return False
    ctx = (context or "").lower()
    return any(k in ctx for k in keywords)
