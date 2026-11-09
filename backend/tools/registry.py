"""Agent tool registry — register, discover, and invoke security tools."""
import json
import re
from typing import Any, Callable, Dict, List, Optional

TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {}


def _extract_json(text: str):
    """Extract the first valid JSON object from LLM output.

    Tries: direct parse → ```json block → JSONDecoder.raw_decode() scanning.
    """
    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    for idx, ch in enumerate(text):
        if ch == "{":
            try:
                decoder = json.JSONDecoder()
                obj, _ = decoder.raw_decode(text[idx:])
                return obj
            except json.JSONDecodeError:
                continue
    return None


def register_tool(
    name: str,
    description: str,
    category: str = "general",
    requires_provider: bool = True,
    expects: str = "any",
    accepts: str = "any",
):
    """Decorator to register a function as an agent-callable tool.

    Args:
        name: Unique tool identifier (e.g. "phishing_analyzer").
        description: Natural language description for the agent to understand when to use this tool.
        category: Grouping key ("recon", "exploit", "report", "general").
        requires_provider: Whether the tool needs an LLM provider parameter injected.
    """

    def decorator(func: Callable) -> Callable:
        TOOL_REGISTRY[name] = {
            "name": name,
            "description": description,
            "category": category,
            "func": func,
            "requires_provider": requires_provider,
            "expects": expects,
            "accepts": accepts,
        }
        return func

    return decorator


def get_tool(name: str) -> Optional[Dict[str, Any]]:
    """Get a single tool by name."""
    return TOOL_REGISTRY.get(name)


def get_all_tools() -> Dict[str, Dict[str, Any]]:
    """Get all registered tools."""
    return dict(TOOL_REGISTRY)


def get_tools_by_category(category: str) -> Dict[str, Dict[str, Any]]:
    """Get tools filtered by category."""
    return {
        name: info
        for name, info in TOOL_REGISTRY.items()
        if info["category"] == category
    }


def list_tool_names() -> List[str]:
    """Return sorted list of registered tool names."""
    return sorted(TOOL_REGISTRY.keys())


def get_tool_descriptions_for_llm() -> str:
    """Format all tool descriptions for inclusion in an LLM system prompt."""
    lines = []
    for name, info in sorted(TOOL_REGISTRY.items()):
        lines.append(f"- **{name}**: {info['description']}")
    return "\n".join(lines)


async def invoke_tool(name: str, **kwargs) -> Any:
    """Invoke a registered tool by name. Passes kwargs to the tool function."""
    tool = get_tool(name)
    if tool is None:
        raise ValueError(f"Unknown tool: {name}. Available: {list_tool_names()}")

    return await tool["func"](**kwargs)
