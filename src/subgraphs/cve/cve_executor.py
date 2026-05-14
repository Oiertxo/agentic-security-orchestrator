import re
from typing import Any, Dict, Optional, Tuple

from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.state import AgentState, CveState
from src.subgraphs.cve.cve_executor_client import call_cve_lookup
from src.utils.utils import get_cvss_severity


@observe(name="CVE executor")
async def cve_executor_node(state: AgentState, config: RunnableConfig) -> AgentState:
    logger.info("[CVE_EXECUTOR] Entering CVE executor")
    old_cve = state.get("cve", {})
    new_step = int(old_cve.get("step_count", 0)) + 1
    current_vulnerabilities = dict(old_cve.get("vulnerabilities", {}))
    analyzed_services_for_cve = old_cve.get("analyzed_services_for_cve", {})
    new_analyzed_services_for_cve = {
        ip: list(ports) for ip, ports in analyzed_services_for_cve.items()
    }

    plan = state["cve"].get("planner", {})

    if not plan:
        return {
            **state,
            "messages": [HumanMessage(content="[CV_EXECUTOR] Error: Empty plan")],
            "cve": {
                **old_cve,
                "results": (old_cve.get("results", []))
                + [{"ok": False, "error": "Empty plan"}],
                "step_count": new_step,
            },
            "next_step": "planner",
        }

    args = plan.get("arguments", {})
    target_ip = args.get("target", "").split(":")[0]
    target_port = args.get("port")

    engine_result = await call_cve_lookup(plan=plan)

    if engine_result.get("ok"):
        response = engine_result.get("response", {})
        items = response.get("items", [])

        # Get versions
        versions = []
        raw_app_version = args.get("app_version")
        raw_service_version = args.get("version")

        if raw_app_version:
            versions.append(normalize_version(raw_app_version))
        if raw_service_version:
            versions.append(normalize_version(raw_service_version))
        if not versions:
            versions.append({"type": "unknown"})

        # 1. Filter applicable items
        applicable_items = []
        for item in items:
            for detected_version in versions:
                if is_cve_applicable(item, detected_version):
                    item["matched_version"] = detected_version
                    applicable_items.append(item)
                    break

        # 2. Filter by threshold and calculate scores
        filtered_items = []
        for item in applicable_items:
            scores = [
                item.get("cvss_v31_base"),
                item.get("cvss_v30_base"),
                item.get("cvss_v2_base"),
            ]
            max_score = max(filter(None, scores), default=0)

            if max_score >= 8.0:
                item["calculated_max_cvss"] = max_score
                item["severity_label"] = get_cvss_severity(scores)
                filtered_items.append(item)

        # 3. SORTING LOGIC: Severity (Calculated CVSS) DESC, then Recency (CVE ID) DESC
        def sort_key(x):
            severity = x.get("calculated_max_cvss", 0)

            # Recency: Extract (Year, ID) from 'CVE-2017-12635' -> (2017, 12635)
            cve_str = x.get("cve_id", "CVE-1970-0")
            parts = cve_str.split("-")
            try:
                year = int(parts[1])
                seq = int(parts[2])
            except (IndexError, ValueError):
                year, seq = 0, 0

            return (severity, year, seq)

        # We sort descending (highest severity and newest year first)
        filtered_items.sort(key=sort_key, reverse=True)

        # 4. Limit to top candidates for exploitation mapping
        # We increase the buffer to 20 to ensure we find at least 10 actual exploits later
        final_candidates = filtered_items[:20]

        # Update vulnerabilities state
        service_key = f"{target_ip}:{target_port}" if target_port else target_ip
        existing_vulns = current_vulnerabilities.get(service_key, [])
        existing_ids = {v.get("cve_id") for v in existing_vulns}
        new_vulns = [v for v in final_candidates if v.get("cve_id") not in existing_ids]
        current_vulnerabilities[service_key] = existing_vulns + new_vulns

        if target_ip and target_port:
            if target_ip not in new_analyzed_services_for_cve:
                new_analyzed_services_for_cve[target_ip] = []
            if target_port not in new_analyzed_services_for_cve[target_ip]:
                new_analyzed_services_for_cve[target_ip].append(target_port)

        summary = {
            "ok": True,
            "tool": "cve_lookup",
            "target": service_key,
            "count": len(final_candidates),
            "top_cves": [x.get("cve_id") for x in final_candidates[:5]],
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
            if (
                info.get("product")
                and info.get("version")
                and port not in analyzed_cve_ip
            ):
                pending_services_for_cve.setdefault(ip, []).append(port)

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
        "cve": updated_cve,
        "next_step": "planner",
    }


def _parse_version_tuple(v: str) -> Optional[Tuple[int, ...]]:
    if not v:
        return None
    clean_v = re.sub(r"[^0-9.]", "", v).strip(".")
    parts = clean_v.split(".")
    try:
        return tuple(int(p) for p in parts if p.isdigit())
    except ValueError:
        return None


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
    logger.warning(
        f"[CVE_EXECUTOR]: DEBUG is cve applicable {item}, {detected_version}"
    )

    # Fail-open
    if detected_version.get("type") == "unknown":
        logger.warning(f"[CVE_EXECUTOR] Unknown version: allow CVE: {item}")
        return True
    configs = item.get("configurations", [])
    if not configs:
        logger.warning(f"[CVE_EXECUTOR] No configurations: allow CVE {item}")
        return True

    for cfg in configs:
        if not any(
            cfg.get(k)
            for k in (
                "versionStartIncluding",
                "versionStartExcluding",
                "versionEndIncluding",
                "versionEndExcluding",
            )
        ):
            continue

        # Parse limits
        start_inc = (
            _parse_version_tuple(cfg["versionStartIncluding"])
            if cfg.get("versionStartIncluding")
            else None
        )
        start_exc = (
            _parse_version_tuple(cfg["versionStartExcluding"])
            if cfg.get("versionStartExcluding")
            else None
        )
        end_inc = (
            _parse_version_tuple(cfg["versionEndIncluding"])
            if cfg.get("versionEndIncluding")
            else None
        )
        end_exc = (
            _parse_version_tuple(cfg["versionEndExcluding"])
            if cfg.get("versionEndExcluding")
            else None
        )

        # -------------------------
        # SINGLE VERSION
        # -------------------------
        if detected_version["type"] == "single":
            v = detected_version["version"]

            lower_ok = (start_inc is None or v >= start_inc) and (
                start_exc is None or v > start_exc
            )

            upper_ok = (end_inc is None or v <= end_inc) and (
                end_exc is None or v < end_exc
            )

            if lower_ok and upper_ok:
                logger.warning("[CVE_EXECUTOR]: DEBUG single match true")
                return True

        # -------------------------
        # RANGE VERSION
        # -------------------------
        elif detected_version["type"] == "range":
            vmin = detected_version["min"]
            vmax = detected_version["max"]

            lower_ok = (start_inc is None or vmax >= start_inc) and (
                start_exc is None or vmax > start_exc
            )

            upper_ok = (end_inc is None or vmin <= end_inc) and (
                end_exc is None or vmin < end_exc
            )

            if lower_ok and upper_ok:
                logger.warning("[CVE_EXECUTOR]: DEBUG range match true")
                return True

    logger.warning("[CVE_EXECUTOR]: DEBUG no matches")
    return False
