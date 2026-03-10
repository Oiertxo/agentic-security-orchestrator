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