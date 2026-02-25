import os, json, re
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, BaseMessage
from src.state import PortMap
from src.state import AgentState
from typing import List, Dict, Any
from copy import deepcopy

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE | re.DOTALL)

def load_prompt(filename: str) -> str:
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    prompt_path = os.path.join(base_path, "src/prompts", filename)
    
    with open(prompt_path, "r", encoding="utf-8") as f:
        return f.read().strip()
    
def _strip_code_fences(s: str) -> str:
    """Remove triple backtick fences, with or without 'json' tag."""
    s = s.strip()
    if s.startswith("```"):
        s = _JSON_FENCE_RE.sub("", s).strip()
    return s

def _extract_first_json_object(s: str) -> str | None:
    """
    Extract the first balanced {...} JSON object from text.
    Simple brace counting; works well for most LLM outputs.
    """
    start = s.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(s)):
        ch = s[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return s[start:i+1]
    return None

def parse_as_json(x: Any) -> Any:
    """
    Parse JSON from:
      - dict → return as-is
      - list → return as-is (or raise if not desired)
      - AIMessage-like (has .content) → parse content
      - string → parse strictly; if fails:
          * strip ``` fences
          * try direct json
          * try extracting first {...} object
    Raise ValueError on failure with a short preview to aid debugging.
    """
    # Case 1: Already a dict
    if isinstance(x, dict):
        return x

    # Case 2: List (you can decide to accept as-is or restrict)
    if isinstance(x, list):
        # If you only expect a single dict in a 1-element list:
        if len(x) == 1 and isinstance(x[0], dict):
            return x[0]
        # Otherwise, allow the list to pass (many models can return arrays)
        return x

    # Case 3: LangChain/LLM message object
    if hasattr(x, "content"):
        return parse_as_json(x.content)

    # Case 4: String content
    if isinstance(x, str):
        s = x.strip()
        # Try direct JSON
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            pass

        # Strip code fences and retry
        s2 = _strip_code_fences(s)
        if s2 != s:
            try:
                return json.loads(s2)
            except json.JSONDecodeError:
                pass

        # Extract first balanced object
        candidate = _extract_first_json_object(s2)
        if candidate:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                # continue to final error
                pass

        preview = s[:200].replace("\n", "\\n")
        raise ValueError(f"Could not parse JSON from string. Preview: {preview!r}")

    # Fallback unsupported type
    raise ValueError(f"Unsupported JSON input type: {type(x)}")

def get_clean_content(messages):
    clean_content = []
    for m in messages:
        content = str(m.content)
        if isinstance(m, HumanMessage):
            clean_content.append(HumanMessage(content=content))
        elif isinstance(m, AIMessage):
            clean_content.append(AIMessage(content=content))
        elif isinstance(m, SystemMessage):
            clean_content.append(SystemMessage(content=content))
    return clean_content


def last_user_message(messages: list[BaseMessage]) -> HumanMessage | None:
    for m in reversed(messages):
        if isinstance(m, HumanMessage) and not str(m.content).startswith("[SOURCE:"):
            return m
    return None

def last_recon_summary(messages: list[BaseMessage]) -> HumanMessage | None:
    for m in reversed(messages):
        if isinstance(m, HumanMessage) and str(m.content).startswith("[SOURCE: recon_engine]"):
            return m
    return None

def last_ai_planner_message(messages: list[BaseMessage]) -> AIMessage | None:
    for m in reversed(messages):
        if isinstance(m, AIMessage):
            return m
    return None

def merge_port_map(old_map: PortMap, new_map: PortMap) -> PortMap:
    merged: PortMap = {}

    # Copy old
    for ip, ports in (old_map or {}).items():
        merged[ip] = {int(p): deepcopy(meta) for p, meta in (ports or {}).items()}

    # Merge new
    for ip, ports in (new_map or {}).items():
        merged.setdefault(ip, {})
        for p, meta in (ports or {}).items():
            p = int(p)
            existing = merged[ip].get(p, {})
            merged[ip][p] = {
                "name": meta.get("name") or existing.get("name"),
                "product": meta.get("product") or existing.get("product"),
                "version": meta.get("version") or existing.get("version"),
                "extrainfo": meta.get("extrainfo") or existing.get("extrainfo"),
                "ostype": meta.get("ostype") or existing.get("ostype"),
            }

    return merged

def derive_pending_hosts(port_map: PortMap, scanned_hosts: List[str]) -> List[str]:
    scanned = set(scanned_hosts or [])
    pending: List[str] = []
    for ip, ports in (port_map or {}).items():
        if ip in scanned:
            continue
        if ports:
            pending.append(ip)
    return pending

def was_version_scan(plan: Dict[str, Any]) -> bool:
    opts = (plan.get("arguments") or {}).get("options") or []
    norm = [(opt or "").strip().lower() for opt in opts]
    return any(
        o == "-sv"
        or o.startswith("-sv")
        or o == "-a"
        or o == "--version-all"
    for o in norm
    )

def target_is_network(target: str) -> bool:
    return "/" in (target or "")

def last_n_messages(messages, n=8):
    return messages[-n:]

    
def supervisor_state_view(state: AgentState) -> dict:
    recon = state.get("recon", {}) or {}
    exploit = state.get("exploit", {}) or {}

    port_map = recon.get("port_map", {})
    trimmed_port_map = {}
    for host_i, (host, ports) in enumerate(port_map.items()):
        if host_i >= 20:
            break
        trimmed_port_map[host] = dict(list(ports.items())[:50])

    return {
        "user_target": state.get("user_target"),
        "next_step": state.get("next_step"),
        "recon": {
            "finished": recon.get("finished", False),
            "scanned_hosts": recon.get("scanned_hosts", []),
            "port_map": trimmed_port_map,
            "step_count": recon.get("step_count"),
        },
        "exploit": {
            **exploit
        },
        "messages": state.get("messages")
    }

def get_engine_url() -> str:
    return os.getenv("EXECUTION_ENGINE_URL", "http://kali-engine:5000")