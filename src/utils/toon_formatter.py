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
    if not vulnerabilities:
        return "vulnerabilities(0): -"
    
    total_cves = sum(len(cves) for cves in vulnerabilities.values())
    header = f"vulnerabilities({total_cves}): target, cve_id, score"
    rows = []
    
    for target, cve_list in vulnerabilities.items():
        for cve in cve_list:
            cve_id = cve.get('cve_id', '-')
            score = cve.get('calculated_max_cvss', '-')
            rows.append(f"{target}, {cve_id}, {score}")
            
    return f"{header}\n" + "\n".join(rows)

def exploits_to_toon(found_exploits: dict) -> str:
    """
    Converts FoundExploit objects or dicts into compact TOON.
    Handles both object attribute access and dictionary keys.
    """
    if not found_exploits:
        return "exploits(0): -"
        
    total = sum(len(exps) for exps in found_exploits.values())
    header = f"exploits({total}): target, edb_id, title"
    rows = []
    
    for target, exploits in found_exploits.items():
        for exp in exploits:
            if hasattr(exp, 'edb_id'):
                eid = getattr(exp, 'edb_id', '-')
                title = getattr(exp, 'title', '-')
            else:
                eid = exp.get('edb_id', exp.get('id', '-'))
                title = exp.get('title', '-')
            
            clean_title = str(title).replace(",", " ").strip()
            rows.append(f"{target}, {eid}, {clean_title}")
            
    return f"{header}\n" + "\n".join(rows)

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