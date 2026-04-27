from typing import Any, Dict, Mapping

from src.state import AttackSurface


def _clean(value):
    if value is None or str(value).strip().lower() in ["none", "null", ""]:
        return "-"
    return str(value).replace(",", " ").strip()


def port_map_to_toon(port_map: dict, step=1) -> str:
    if not port_map:
        if step == 0:
            return "Discovery not done yet"
        return "services[0]"

    services_count = sum(len(ports) for ports in port_map.values())
    header = f"services[{services_count}]{{ip,port,name,product,version}}"
    rows = []

    for ip, ports in port_map.items():
        for port, info in ports.items():
            rows.append(
                f"{ip},{port},"
                f"{_clean(info.get('name'))},"
                f"{_clean(info.get('product'))},"
                f"{_clean(info.get('version'))}"
            )

    return header + "\n" + "\n".join(rows)


def vulnerabilities_to_toon(vulnerabilities: dict) -> str:
    """
    Converts CVE findings into a compact TOON table including severity labels.
    Format: target, cve_id, score, severity
    """
    if not vulnerabilities:
        return "vulnerabilities[0]"

    rows = []
    for target, cve_list in vulnerabilities.items():
        for cve in cve_list:
            cve_id = cve.get("cve_id", "-")
            score = cve.get("calculated_max_cvss", "-")
            severity = cve.get("severity_label", "-").upper()
            rows.append(
                f"{target},{cve_id},{score if score is not None else '-'},{severity}"
            )

    header = f"vulnerabilities[{len(rows)}]{{target,cve_id,score,severity}}"
    return header + "\n" + "\n".join(rows)


def found_exploits_to_toon(found_exploits: dict) -> str:
    """
    Converts found exploits and framework modules into a compact TOON table.
    """

    if not found_exploits:
        return "exploits[0]"

    rows = []

    for target, entry in found_exploits.items():
        # --- ExploitDB exploits ---
        for exp in entry.get("exploits", []):
            eid = exp.get("edb_id", "-")
            title = exp.get("title", "-")
            clean_title = str(title).replace(",", " ").strip()
            rows.append(f"{target},exploitdb,{eid},{clean_title}")

        # --- Framework modules ---
        for module in entry.get("framework_modules", []):
            rows.append(f"{target},framework,{module},-")

    header = f"exploits[{len(rows)}]:target,type,id_or_path,title"
    return f"{header}\n" + "\n".join(rows)


def pending_services_for_search_to_toon(pending_data: dict) -> str:
    if not pending_data:
        return "No pending services for search"

    total_count = sum(len(services) for services in pending_data.values())

    header = f"pending_search[{total_count}]:ip,port,product,version"
    rows = []

    for ip, services in pending_data.items():
        for svc in services:
            port = svc.get("port", "-")
            prod = _clean(svc.get("product"))
            ver = _clean(svc.get("version"))
            rows.append(f"{ip},{port},{prod},{ver}")

    return f"{header}\n" + "\n".join(rows)


def get_minimal_toon_context(values: dict) -> str:
    """
    Aggregates all TOON-formatted tables into a single compact string
    to drastically reduce LLM inference time.
    """
    target = values.get("user_target", "unknown")
    port_map = values.get("recon", {}).get("port_map", {})
    vulnerabilities = values.get("cve", {}).get("vulnerabilities", {})
    found_exploits = values.get("vuln_map", {}).get("found_exploits", {})

    toon_report = [
        f"TARGET_RANGE: {target}",
        "---",
        port_map_to_toon(port_map),
        "---",
        vulnerabilities_to_toon(vulnerabilities),
        "---",
        found_exploits_to_toon(found_exploits),
    ]

    return "\n".join(toon_report)


def exploit_results_to_toon(exploit_state: Mapping[str, Any]) -> str:
    """
    Converts successful exploitation results into a compact TOON table.
    Focuses ONLY on confirmed compromise evidence.
    """

    if not exploit_state or not exploit_state.get("finished"):
        return "exploitation[0]"

    results = exploit_state.get("results", [])
    compromised = exploit_state.get("compromised_targets", {})

    if not results or not compromised:
        return "exploitation[0]"

    rows = []

    for result in results:
        if result.get("status") != "SUCCESS":
            continue

        target = result.get("target", "-")
        port = result.get("port", "-")

        raw_tool = result.get("tool", "-")
        exploit_id = (
            raw_tool.replace("exploit-", "EDB-")
            if raw_tool.startswith("exploit-")
            else raw_tool
        )

        artifact = result.get("artifact", {})
        probe = artifact.get("probe", {})

        privilege = _clean(probe.get("whoami", "unknown"))

        # Proof: prefer id(), fallback to whoami / hostname
        proof_parts = []
        if probe.get("id"):
            proof_parts.append(f"id={probe['id']}")
        if probe.get("hostname"):
            proof_parts.append(f"host={probe['hostname']}")

        proof = " | ".join(proof_parts) if proof_parts else "-"

        rows.append(f"{target},{port},{exploit_id},{privilege},{proof}")

    if not rows:
        return "exploitation[0]"

    header = f"exploitation[{len(rows)}]:target,port,exploit_id,privilege,proof"

    return f"{header}\n" + "\n".join(rows)


def pending_surfaces_to_toon(pending_surfaces: Dict[str, AttackSurface]) -> str:
    """
    Convert pending_surfaces into TOON format for exploit planner.
    Format:
    pending_surfaces[N]{surface_id,service,product,port,cves,available_exploits,attempted_exploits}
    """

    count = len(pending_surfaces)
    header = (
        f"pending_surfaces[{count}]"
        "{surface_id,service,product,port,cves,available_exploits,attempted_exploits}"
    )

    if not pending_surfaces:
        return header

    rows = []

    for surface_id, surface in pending_surfaces.items():
        service = surface.get("service", "-")
        product = surface.get("product") or "-"
        port = surface_id.split(":")[-1]

        # CVEs
        cves = surface.get("cves", [])
        cves_str = "|".join(cves) if cves else "-"

        # Available exploits (using next_tool IDs, as you decided)
        exploit_ids = surface.get("exploit_ids", [])
        available_exploits = "|".join(exploit_ids) if exploit_ids else "-"

        # Attempted exploits history
        attempted_map = surface.get("attempted_exploits", {})
        attempted_exploits = (
            "|".join(f"{k}:{v}" for k, v in attempted_map.items())
            if attempted_map
            else "-"
        )

        rows.append(
            f"{surface_id},"
            f"{service},"
            f"{product},"
            f"{port},"
            f"{cves_str},"
            f"{available_exploits},"
            f"{attempted_exploits}"
        )

    return header + "\n" + "\n".join(rows)
