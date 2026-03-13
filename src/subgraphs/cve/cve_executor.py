from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from src.state import AgentState, CveState
from src.subgraphs.cve.cve_executor_client import call_cve_lookup
from src.utils.utils import parse_as_json, get_cvss_severity
from src.logger import logger
from langfuse import observe
import json

@observe(name="CVE executor")
async def cve_executor_node(state: AgentState, config: RunnableConfig) -> AgentState:
    logger.info(f"[CVE_EXECUTOR] Received state: {state}")
    old_cve = state.get("cve", {})
    new_step = int(old_cve.get("step_count", 0)) + 1
    current_vulnerabilities = dict(old_cve.get("vulnerabilities", {}))
    analyzed_services_for_cve = old_cve.get("analyzed_services_for_cve", {})
    new_analyzed_services_for_cve = {ip: list(ports) for ip, ports in analyzed_services_for_cve.items()}

    raw = state["messages"][-1].content
    logger.info(f"[CVE_EXECUTOR_NODE] plan: {raw}")
    try:
        plan = parse_as_json(raw)
    except Exception:
        result = {"ok": False, "error": "planner_output_not_json", "raw": raw}
        return {
            **state,
            "messages": [HumanMessage(content=f"[SOURCE: cve_lookup]\n{json.dumps(result)}")],
            "cve": {**old_cve, "results": (old_cve.get("results", [])) + [result], "step_count": new_step},
            "next_step": "planner"
        }

    args = plan.get("arguments", {})
    target_ip = args.get("target").split(":")[0]
    target_port = args.get("port")
    
    engine_result = await call_cve_lookup(plan=plan)

    logger.warning(f"Engine_result: {engine_result}")
        
    if engine_result.get("ok"):
        response = engine_result.get("response", {})
        items = response.get("items", [])

        filtered_items = [
            item for item in items 
            if (item.get("cvss_v31_base") and item["cvss_v31_base"] >= 8.0) or 
            (item.get("cvss_v2_base") and item["cvss_v2_base"] >= 8.0)
        ]

        for item in filtered_items:
            item['calculated_max_cvss'] = max(filter(None, [item.get('cvss_v31_base'), item.get('cvss_v2_base')]), default=0)
            item['severity_label'] = get_cvss_severity([item.get('cvss_v31_base'), item.get('cvss_v2_base')])
        
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
            "top_cves": [x.get("cve_id") for x in filtered_items[:5]]
        }
    else:
        summary = {"ok": False, "error": engine_result.get("error"), "tool": "cve_lookup"}

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
    logger.info(f"[CVE_EXECUTOR] Pending services for CVE lookup: {sum(len(p) for p in pending_services_for_cve.values())}")

    updated_cve: CveState = {
        **old_cve,
        "results": (old_cve.get("results", [])) + [summary],
        "step_count": new_step,
        "vulnerabilities": current_vulnerabilities,
        "analyzed_services_for_cve": new_analyzed_services_for_cve,
        "pending_services_for_cve": pending_services_for_cve,
        "finished": False
    }

    return {
        **state,
        "user_target": state.get("user_target"),
        "cve": updated_cve,
        "next_step": "planner",
    }