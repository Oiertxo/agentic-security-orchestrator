def _clean(value):
    if value is None or str(value).strip().lower() in ['none', 'null', '']:
        return "-"
    return str(value).replace(",", " ").strip()

def port_map_to_toon(port_map: dict) -> str:
    if not port_map:
        return "services(0): -"
    
    services_count = sum(len(ports) for ports in port_map.values())
    header = f"services({services_count}): ip, port, name, product, version"
    rows = []
    
    for ip, ports in port_map.items():
        for port, info in ports.items():
            rows.append(
                f"{ip}, {port}, "
                f"{_clean(info.get('name'))}, "
                f"{_clean(info.get('product'))}, "
                f"{_clean(info.get('version'))}"
            )
    
    return f"{header}\n" + "\n".join(rows)

def vulnerabilities_to_toon(vulnerabilities: dict) -> str:
    """
    Converts CVE findings into a compact TOON table including severity labels.
    Format: target, cve_id, score, severity
    """
    if not vulnerabilities:
        return "vulnerabilities(0): -"
    
    all_rows = []
    for target, cve_list in vulnerabilities.items():
        for cve in cve_list:
            cve_id = cve.get('cve_id', '-')
            score = cve.get('calculated_max_cvss', '-')
            severity = cve.get('severity_label', '-').upper()
            
            all_rows.append(f"{target}, {cve_id}, {score}, {severity}")
    
    if not all_rows:
        return "vulnerabilities(0): -"

    header = f"vulnerabilities({len(all_rows)}): target, cve_id, score, severity"
    return f"{header}\n" + "\n".join(all_rows)

def found_exploits_to_toon(found_exploits: dict) -> str:
    """
    Converts FoundExploit dicts into compact TOON table.
    Assumes state is normalized as dictionaries via model_dump().
    """
    if not found_exploits:
        return "exploits(0): -"
        
    all_rows = []
    for target, exploits in found_exploits.items():
        for exp in exploits:
            eid = exp.get('edb_id', '-')
            title = exp.get('title', '-')
            local_path = exp.get('local_path', '-')
            clean_title = str(title).replace(",", " ").strip()
            all_rows.append(f"{target}, {eid}, {clean_title}, {local_path}")
            
    if not all_rows:
        return "exploits(0): -"

    header = f"exploits({len(all_rows)}): target, edb_id, title, local_path"
    return f"{header}\n" + "\n".join(all_rows)

def pending_services_for_search_to_toon(pending_data: dict) -> str:
    if not pending_data:
        return "pending_search(0): -"
    
    total_count = sum(len(services) for services in pending_data.values())
    
    header = f"pending_search({total_count}): ip, port, product, version"
    rows = []
    
    for ip, services in pending_data.items():
        for svc in services:
            port = svc.get("port", "-")
            prod = _clean(svc.get("product"))
            ver = _clean(svc.get("version"))
            rows.append(f"{ip}, {port}, {prod}, {ver}")
            
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
        found_exploits_to_toon(found_exploits)
    ]
    
    return "\n".join(toon_report)

def thoughts_to_toon(thought_log) -> str:
    if not thought_log:
        return ""

    formatted_steps = []
    
    noise_patterns = [
        "Welcome to Ubuntu", " * ", "Documentation:", "Management:", 
        "Support:", "Last login:", "Pseudo-terminal", "Warning: Permanently added",
        "mesg: ttyname failed"
    ]
    
    tech_errors = ["TabError", "SyntaxError", "No such file", "IndentationError", "can't open file"]

    for entry in thought_log:
        step = entry.get("step", "?")
        action = entry.get("action", "Unknown")
        raw_result = entry.get("result", "No result recorded")
        
        if any(err in str(raw_result) for err in tech_errors):
            clean_result = "FAILED: Technical error (Script incompatible or environment issue)."
        
        else:
            lines = str(raw_result).splitlines()
            filtered_lines = [
                line.strip() for line in lines 
                if not any(noise in line for noise in noise_patterns) and line.strip()
            ]
            
            clean_result = "\n".join(filtered_lines) if filtered_lines else str(raw_result)[:100]
            
            if len(clean_result) > 200:
                clean_result = clean_result[:200] + " [...]"

        step_str = f"[S{step}] Action: {action} -> Result: {clean_result}"
        formatted_steps.append(step_str)

    return "\n".join(formatted_steps)