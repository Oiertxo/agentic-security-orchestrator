import hashlib
import json
import os
import re
from copy import deepcopy
from typing import Any, Dict, List, Optional

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage

from src.state import AgentState, PortMap, ServiceMeta, TokenCount

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE | re.DOTALL)


def load_prompt(filename: str) -> str:
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    prompt_path = os.path.join(base_path, "prompts", filename)

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
                return s[start : i + 1]
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
        for item in x:
            if isinstance(item, dict):
                return item
        raise ValueError("List does not contain valid JSON object")

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
        if isinstance(m, HumanMessage) and str(m.content).startswith(
            "[SOURCE: recon_engine]"
        ):
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

            new_meta: ServiceMeta = deepcopy(existing)

            for k, v in meta.items():
                if v is not None:
                    new_meta[k] = v

            merged[ip][p] = new_meta

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
    opts = (plan.get("arguments", {})).get("options", [])
    norm = [(opt or "").strip().lower() for opt in opts]
    return any(
        o == "-sv" or o.startswith("-sv") or o == "-a" or o == "--version-all"
        for o in norm
    )


def target_is_network(target: str) -> bool:
    return "/" in (target or "")


def last_n_messages(messages, n=8):
    return messages[-n:]


def supervisor_state_view(state: AgentState) -> dict:
    recon = state.get("recon", {})
    cve = state.get("cve", {})
    vuln_map = state.get("vuln_map", {})
    exploit = state.get("exploit", {})

    def get_last_result(data_dict):
        results = data_dict.get("results", [])
        return results[-1] if results else {}

    return {
        "user_target": state.get("user_target"),
        "recon": {
            "finished": recon.get("finished", False),
            "scanned_hosts": recon.get("scanned_hosts", []),
            "results": get_last_result(recon),
        },
        "cve": {
            "finished": cve.get("finished", False),
            "results": get_last_result(cve),
        },
        "vuln_map": {
            "finished": vuln_map.get("finished", False),
            "results": get_last_result(vuln_map),
        },
        "exploit": {
            "finished": exploit.get("finished", False),
            "results": get_last_result(exploit),
        },
        "message_history": state.get("messages"),
        "report_finished": state.get("report_finished", False),
    }


def get_engine_url() -> str:
    return os.getenv("EXECUTION_ENGINE_URL", "http://kali-engine:5000")


def get_cvss_severity(cvss_list):
    scores = [s for s in cvss_list if s is not None]
    max_score = max(scores) if scores else 0
    if max_score >= 9.0:
        return "CRITICAL"
    if max_score >= 7.0:
        return "HIGH"
    if max_score >= 4.0:
        return "MEDIUM"
    return "LOW"


def normalize_newlines_python(script: str) -> str:
    script = re.sub(r'(?<!b)"\\n', '"\n', script)
    script = re.sub(r"(?<!b)'\\n", "'\n", script)
    return script


VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3})")


def normalize_version(raw: Optional[str]) -> Optional[str]:
    if not isinstance(raw, str):
        return None

    raw = raw.strip()
    if raw == "" or raw.lower() in {"-", "unknown", "n/a"}:
        return None

    match = VERSION_RE.search(raw)
    if not match:
        return None

    return match.group(1)


def update_state_tokens(callback, state):
    new_tokens: TokenCount = {
        "prompt_tokens": callback.prompt_tokens,
        "prompt_tokens_cached": callback.prompt_tokens_cached,
        "completion_tokens": callback.completion_tokens,
        "reasoning_tokens": callback.reasoning_tokens,
        "total_tokens": callback.total_tokens,
    }

    state_tokens: TokenCount = state["tokens"]["token_count"]

    for k, v in new_tokens.items():
        state_tokens[k] += v

    return state_tokens, new_tokens


def compute_hash(body: str) -> str:
    return hashlib.md5(body.encode()).hexdigest()
