from langchain_core.messages import HumanMessage
from src.subgraphs.recon.state import ReconState, derive_pending_hosts, merge_port_map, target_is_network, was_version_scan
from src.subgraphs.recon.executor_client import call_recon_engine
from src.utils import parse_as_json
from src.logger import logger
from xml.etree import ElementTree
from typing import Dict, List, Any
import json

def recon_executor_node(state: ReconState):
    step = int(state.get("step_count", 0)) + 1

    raw = state["messages"][-1].content
    logger.info(f"[RECON_EXECUTOR_NODE] plan: {parse_as_json(raw)}")
    try:
        plan = parse_as_json(raw)
    except Exception:
        result = {"ok": False, "error": "planner_output_not_json", "raw": raw}
        return {
            "messages": [HumanMessage(content=f"[SOURCE: recon_engine]\n{json.dumps(result)}")],
            "results": [result],
            "step_count": step,
            "port_map": state.get("port_map") or {},
            "scanned_hosts": state.get("scanned_hosts") or [],
            "pending_hosts": state.get("pending_hosts") or [],
            "done": False,
        }


    engine_result = call_recon_engine(plan=plan)

    new_port_map = state.get("port_map") or {}
    new_scanned = state.get("scanned_hosts") or []

    if not engine_result.get("ok"):
        summary = {
            "ok": False,
            "error": engine_result.get("error", "Unknown executor error"),
            "request": engine_result.get("request"),
            "response": engine_result.get("response"),
        }
    else:
        response = engine_result.get("response") or {}
        xml_str = response.get("stdout")

        if not xml_str:
            summary = {
                "ok": False,
                "error": "Executor returned no stdout",
                "response": response
            }
        else:
            summary = summarize_nmap_xml(xml_str)
            
            new_port_map = merge_port_map(state.get("port_map") or {}, summary)
            new_scanned = list(state.get("scanned_hosts") or [])
            if was_version_scan(plan):
                target = (plan.get("arguments") or {}).get("target")
                if target and not target_is_network(target) and target not in new_scanned:
                    new_scanned.append(target)

    new_pending = derive_pending_hosts(new_port_map, new_scanned)
    logger.info(f"[RECON_EXECUTOR] Recon engine result: {summary}")

    return {
        "messages": [HumanMessage(content=f"[SOURCE: recon_engine]\n{json.dumps(summary)}")],
        "results": [summary],
        "step_count": step,
        "port_map": new_port_map,
        "scanned_hosts": new_scanned,
        "pending_hosts": new_pending,
        "done": False,
    }

def summarize_nmap_xml(xml_str: str) -> Dict[str, Any]:
    try:
        root = ElementTree.fromstring(xml_str)
    except ElementTree.ParseError:
        return {"error": "invalid_xml"}

    hosts_summary = []
    scanning_time = 0
    scan_finished_time = 0

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue

        ip = addr_el.get("addr", None)
        if ip is None:
            continue

        open_ports: List[int] = []
        services: List[Dict] = []
        ports_parent = host.find("ports")

        if ports_parent is not None:
            for port in ports_parent.findall("port"):
                portid = port.get("portid")
                if portid is None:
                    continue
                state_el = port.find("state")
                if state_el is None:
                    continue

                state_value = state_el.get("state", None)
                if state_value == "open":
                    open_ports.append(int(portid))
                    service_el = port.find("service")
                    services.append({
                        "port": int(portid),
                        "name": service_el.get("name") if service_el is not None else None,
                        "product": service_el.get("product") if service_el is not None else None,
                        "version": service_el.get("version") if service_el is not None else None,
                        "extrainfo": service_el.get("extrainfo") if service_el is not None else None,
                        "ostype": service_el.get("ostype") if service_el is not None else None,
                    })

        runstats = root.find("runstats/finished")
        scanning_time = runstats.get("elapsed") if runstats is not None else None
        scan_finished_time = runstats.get("timestr") if runstats is not None else None

        hosts_summary.append({
            "ip": ip,
            "open_ports": open_ports,
            "services": services,
        })

    return {
        "summary": {
            "hosts_found": len(hosts_summary),
            "scanning_time": scanning_time,
            "finished_at": scan_finished_time,
        },
        "hosts": hosts_summary,
    }