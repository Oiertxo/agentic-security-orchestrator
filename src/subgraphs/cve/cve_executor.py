import json
import re
from typing import Any, Dict, Optional, Tuple

from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.state import AgentState, CveState
from src.subgraphs.cve.cve_executor_client import call_cve_lookup
from src.utils.utils import get_cvss_severity, parse_as_json


@observe(name="CVE executor")
async def cve_executor_node(state: AgentState, config: RunnableConfig) -> AgentState:
    logger.info(f"[CVE_EXECUTOR] Received state: {state}")
    old_cve = state.get("cve", {})
    new_step = int(old_cve.get("step_count", 0)) + 1
    current_vulnerabilities = dict(old_cve.get("vulnerabilities", {}))
    analyzed_services_for_cve = old_cve.get("analyzed_services_for_cve", {})
    new_analyzed_services_for_cve = {
        ip: list(ports) for ip, ports in analyzed_services_for_cve.items()
    }

    raw = state["messages"][-1].content
    logger.info(f"[CVE_EXECUTOR] plan: {raw}")
    try:
        plan = parse_as_json(raw)
    except Exception:
        result = {"ok": False, "error": "planner_output_not_json", "raw": raw}
        return {
            **state,
            "messages": [
                HumanMessage(content=f"[SOURCE: cve_lookup]\n{json.dumps(result)}")
            ],
            "cve": {
                **old_cve,
                "results": (old_cve.get("results", [])) + [result],
                "step_count": new_step,
            },
            "next_step": "planner",
        }

    args = plan.get("arguments", {})
    target_ip = args.get("target").split(":")[0]
    target_port = args.get("port")

    engine_result = await call_cve_lookup(plan=plan)

    logger.info(f"[CVE_EXECUTOR] Engine_result: {engine_result}")

    if engine_result.get("ok"):
        response = engine_result.get("response", {})
        items = response.get("items", [])

        detected_version = normalize_version(args.get("version"))

        applicable_items = [
            item for item in items if is_cve_applicable(item, detected_version)
        ]

        filtered_items = [
            item
            for item in applicable_items
            if (item.get("cvss_v31_base") and item["cvss_v31_base"] >= 8.0)
            or (item.get("cvss_v2_base") and item["cvss_v2_base"] >= 8.0)
        ]

        for item in filtered_items:
            item["calculated_max_cvss"] = max(
                filter(None, [item.get("cvss_v31_base"), item.get("cvss_v2_base")]),
                default=0,
            )
            item["severity_label"] = get_cvss_severity(
                [item.get("cvss_v31_base"), item.get("cvss_v2_base")]
            )

        # Update vulnerabilities
        service_key = f"{target_ip}:{target_port}" if target_port else target_ip
        existing_vulns = current_vulnerabilities.get(service_key, [])
        existing_ids = {v.get("cve_id") for v in existing_vulns}
        new_vulns = [v for v in filtered_items if v.get("cve_id") not in existing_ids]
        current_vulnerabilities[service_key] = existing_vulns + new_vulns

        # Update lists
        if target_ip and target_port:
            if target_ip not in new_analyzed_services_for_cve:
                new_analyzed_services_for_cve[target_ip] = []
            if target_port not in new_analyzed_services_for_cve[target_ip]:
                new_analyzed_services_for_cve[target_ip].append(target_port)

        summary = {
            "ok": True,
            "tool": "cve_lookup",
            "target": service_key,
            "count": len(filtered_items),
            "top_cves": [x.get("cve_id") for x in filtered_items[:5]],
        }
    else:
        summary = {
            "ok": False,
            "error": engine_result.get("error"),
            "tool": "cve_lookup",
        }

    port_map = state.get("recon", {}).get("port_map", {})
    pending_services_for_cve = {}

    for ip, ports in port_map.items():
        analyzed_cve_ip = new_analyzed_services_for_cve.get(ip, [])

        for port, info in ports.items():
            product = info.get("product")
            version = info.get("version")

            if product and version:
                if port not in analyzed_cve_ip:
                    pending_services_for_cve.setdefault(ip, []).append(port)

    logger.info(f"[CVE_EXECUTOR] Result summary: {summary}")
    logger.info(
        f"[CVE_EXECUTOR] Pending services for CVE lookup: {sum(len(p) for p in pending_services_for_cve.values())}"
    )

    updated_cve: CveState = {
        **old_cve,
        "results": (old_cve.get("results", [])) + [summary],
        "step_count": new_step,
        "vulnerabilities": current_vulnerabilities,
        "analyzed_services_for_cve": new_analyzed_services_for_cve,
        "pending_services_for_cve": pending_services_for_cve,
        "finished": False,
    }

    return {
        **state,
        "user_target": state.get("user_target"),
        "cve": updated_cve,
        "next_step": "planner",
    }


def _parse_version_tuple(v: str) -> Optional[Tuple[int, ...]]:
    """
    Parse a numeric version string into a tuple.
    Examples:
      "1.2.3" → (1, 2, 3)
      "4.7"   → (4, 7)
    """
    parts = v.split(".")
    nums = []
    for p in parts:
        if not p.isdigit():
            return None
        nums.append(int(p))
    return tuple(nums)


def normalize_version(raw_version: Optional[str]) -> Dict[str, Any]:
    """
    Normalize a raw version string (e.g. from nmap) into a comparable structure.

    Returns:
      {
        "raw": str,
        "type": "single" | "range" | "unknown",
        "version": tuple[int]            # if single
        "min": tuple[int], "max": tuple  # if range
      }
    """
    if not raw_version or not isinstance(raw_version, str):
        return {"raw": raw_version, "type": "unknown"}

    raw = raw_version.strip()

    # --- Case 1: explicit range (e.g. "8.3.0 - 8.3.7")
    range_match = re.search(r"(\d+(?:\.\d+)+)\s*-\s*(\d+(?:\.\d+)+)", raw)
    if range_match:
        vmin = _parse_version_tuple(range_match.group(1))
        vmax = _parse_version_tuple(range_match.group(2))
        if vmin and vmax:
            return {
                "raw": raw,
                "type": "range",
                "min": vmin,
                "max": vmax,
            }

    # --- Case 2: OpenSSH-style patchlevel (e.g. "4.7p1")
    patch_match = re.search(r"(\d+(?:\.\d+)*)(?:p(\d+))", raw)
    if patch_match:
        base = patch_match.group(1)
        patch = int(patch_match.group(2))
        base_tuple = _parse_version_tuple(base)
        if base_tuple:
            return {
                "raw": raw,
                "type": "single",
                "version": base_tuple + (patch,),
            }

    # --- Case 3: generic numeric version (e.g. "5.0.51a-3ubuntu5")
    generic_match = re.search(r"(\d+(?:\.\d+)+)", raw)
    if generic_match:
        base = generic_match.group(1)
        base_tuple = _parse_version_tuple(base)
        if base_tuple:
            return {
                "raw": raw,
                "type": "single",
                "version": base_tuple,
            }

    # --- Fallback
    return {"raw": raw, "type": "unknown"}


def is_cve_applicable(item: Dict, detected_version: Dict) -> bool:
    """
    Decide if a CVE applies to the detected version.

    item:
      {
        "cve_id": "...",
        "configurations": [
            {
                "criteria": "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "1.2.0",
                "versionEndExcluding": "1.3.0"
            }
        ]
      }

    detected_version:
      output of normalize_version()
    """

    if detected_version.get("type") == "unknown":
        return True

    configs = item.get("configurations", [])
    if not configs:
        return True

    for cfg in configs:
        v_start_inc = cfg.get("versionStartIncluding")
        v_start_exc = cfg.get("versionStartExcluding")
        v_end_inc = cfg.get("versionEndIncluding")
        v_end_exc = cfg.get("versionEndExcluding")

        # Single value version
        if detected_version["type"] == "single":
            v = detected_version["version"]

            if v_start_inc:
                if not v >= tuple(map(int, v_start_inc.split("."))):
                    continue

            if v_start_exc:
                if not v > tuple(map(int, v_start_exc.split("."))):
                    continue

            if v_end_inc:
                if not v <= tuple(map(int, v_end_inc.split("."))):
                    continue

            if v_end_exc:
                if not v < tuple(map(int, v_end_exc.split("."))):
                    continue

            return True

        # Range of versions (e.g. "8.3.0 - 8.3.7")
        elif detected_version["type"] == "range":
            vmin = detected_version["min"]
            vmax = detected_version["max"]

            # Intersection between ranges
            if v_start_inc and vmax < tuple(map(int, v_start_inc.split("."))):
                continue

            if v_start_exc and vmax <= tuple(map(int, v_start_exc.split("."))):
                continue

            if v_end_inc and vmin > tuple(map(int, v_end_inc.split("."))):
                continue

            if v_end_exc and vmin >= tuple(map(int, v_end_exc.split("."))):
                continue

            return True

    return False
