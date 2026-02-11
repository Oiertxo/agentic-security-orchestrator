from __future__ import annotations
from typing import Any, Dict, Optional
from src.logger import logger
import os, time, httpx

def _get_base_url() -> str:
    return os.getenv("RECON_ENGINE_URL", "http://kali-engine:5000")


def _normalize_payload(
    tool: Optional[str] = None,
    args: Optional[Dict[str, Any]] = None,
    plan: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Normalize different call styles into the Recon Engine request schema:
      {
        "tool": "nmap" | "dig",
        "target": "192.168.1.13",
        "options": ["-sV", "-Pn"]
      }

    Accepts either:
      - explicit (tool, args) where args contains "target" and optional "options"
      - a 'plan' dict shaped like {"tool": "...", "arguments": {...}}

    Raises ValueError for missing required fields.
    """
    if plan is not None:
        if tool is not None or args is not None:
            raise ValueError("Provide either (plan) OR (tool, args), not both.")

        tool = plan.get("tool")
        arguments = plan.get("arguments", {}) or {}
        target = arguments.get("target")
        options = arguments.get("options", [])
    else:
        arguments = args or {}
        target = arguments.get("target")
        options = arguments.get("options", [])

    if not tool:
        raise ValueError("Missing 'tool' in recon plan.")
    if not target:
        raise ValueError("Missing 'target' in recon plan arguments.")

    # Ensure list for options
    if options is None:
        options = []
    if not isinstance(options, list):
        raise ValueError("'options' must be a list of strings.")

    return {
        "tool": tool,
        "target": target,
        "options": options,
    }


def call_recon_engine(
    *,
    tool: Optional[str] = None,
    args: Optional[Dict[str, Any]] = None,
    plan: Optional[Dict[str, Any]] = None,
    base_url: Optional[str] = None,
    timeout: float = 60.0,
    retries: int = 2,
    backoff_base: float = 0.5,
) -> Dict[str, Any]:
    
    payload = _normalize_payload(tool=tool, args=args, plan=plan)
    base = base_url or _get_base_url()
    url = f"{base.rstrip('/')}/run_mock"

    attempt = 0
    last_exc: Optional[Exception] = None

    while attempt <= retries:
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, json=payload, headers={"Content-Type": "application/json"})
            try:
                data = resp.json()
                logger.info(f"[EXECUTOR_CLIENT] Response: {resp}")
            except Exception:
                data = None

            if resp.status_code < 400:
                return {
                    "ok": True,
                    "status_code": resp.status_code,
                    "request": payload,
                    "response": data,
                    "error": None,
                }
            else:
                # Non-2xx response
                return {
                    "ok": False,
                    "status_code": resp.status_code,
                    "request": payload,
                    "response": data,
                    "error": (data.get("detail") if isinstance(data, dict) and "detail" in data
                              else f"HTTP {resp.status_code}"),
                }

        except (httpx.ConnectError, httpx.ReadTimeout, httpx.HTTPError) as e:
            last_exc = e
            if attempt == retries:
                break
            sleep_s = backoff_base * (2 ** attempt)
            time.sleep(sleep_s)
            attempt += 1

    return {
        "ok": False,
        "status_code": None,
        "request": payload,
        "response": None,
        "error": str(last_exc) if last_exc else "Unknown transport error",
    }