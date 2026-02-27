from langchain_core.messages import HumanMessage
from src.state import AgentState, ReconState, PortMap, ServiceMeta
from src.subgraphs.recon.recon_executor_client import call_recon_engine
from src.utils import parse_as_json, derive_pending_hosts, merge_port_map, target_is_network, was_version_scan
from src.logger import logger
from xml.etree import ElementTree
from typing import Dict, List, Any, Optional
from langfuse import observe
import json

@observe(name="Recon executor")
def recon_executor_node(state: AgentState) -> AgentState:
    recon_state = state.get("recon", {}) or {}
    new_step = int(recon_state.get("step_count", 0)) + 1

    raw = state["messages"][-1].content
    logger.info(f"[RECON_EXECUTOR_NODE] plan: {raw}")
    try:
        plan = parse_as_json(raw)
    except Exception:
        result = {"ok": False, "error": "planner_output_not_json", "raw": raw}
        return {
            **state,
            "recon": {
                "step_count": new_step,
                "port_map": recon_state.get("port_map") or {},
                "scanned_hosts": recon_state.get("scanned_hosts") or [],
                "pending_hosts": recon_state.get("pending_hosts") or [],
                "finished": False,
            },
            "messages": [HumanMessage(content=f"[SOURCE: recon_engine]\n{json.dumps(result)}")],
        }

    engine_result = call_recon_engine(plan=plan)

    new_port_map = recon_state.get("port_map") or {}
    new_scanned = recon_state.get("scanned_hosts") or []

    if not engine_result.get("ok"):
        summary = {
            "ok": False,
            "error": engine_result.get("error", "Unknown executor error"),
            "scanning_time": (engine_result.get("summary", {})).get("scanning_time", 0),
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
            parsed = parse_nmap_xml(xml_str)
            summary = parsed["summary"]
            
            new_port_map = merge_port_map(recon_state.get("port_map") or {}, parsed["port_map"])
            new_scanned = list(recon_state.get("scanned_hosts") or [])
            if was_version_scan(plan):
                target = (plan.get("arguments") or {}).get("target")
                if target and not target_is_network(target) and target not in new_scanned:
                    new_scanned.append(target)

    new_pending = derive_pending_hosts(new_port_map, new_scanned)
    logger.info(f"[RECON_EXECUTOR] Recon engine result: {summary}")
    updated_recon: ReconState = {
        **recon_state,
        "results": (recon_state.get("results") or []) + [summary],
        "step_count": new_step,
        "finished": False,
        "port_map": new_port_map,
        "scanned_hosts": new_scanned,
        "pending_hosts": new_pending,
    }

    return {
        **state,
        "recon": updated_recon,
        "next_step": "planner"
    }

def parse_nmap_xml(xml_str: str) -> Dict[str, Any]:
    try:
        root = ElementTree.fromstring(xml_str)
    except ElementTree.ParseError:
        return {"ok": False, "error": "invalid_xml"}

    runstats = root.find("runstats/finished")
    scanning_time = runstats.get("elapsed") if runstats is not None else None
    finished_at = runstats.get("timestr") if runstats is not None else None

    port_map: PortMap = {}
    hosts_found = 0

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue

        ip = addr_el.get("addr")
        if not ip:
            continue

        hosts_found += 1
        ip_ports = port_map.setdefault(ip, {})

        ports_parent = host.find("ports")
        if ports_parent is None:
            continue

        for port in ports_parent.findall("port"):
            portid = port.get("portid")
            if portid is None:
                continue

            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            p = int(portid)

            service_el = port.find("service")
            meta: ServiceMeta = {
                "name": service_el.get("name") if service_el is not None else None,
                "product": service_el.get("product") if service_el is not None else None,
                "version": service_el.get("version") if service_el is not None else None,
                "extrainfo": service_el.get("extrainfo") if service_el is not None else None,
                "ostype": service_el.get("ostype") if service_el is not None else None,
            }

            existing = ip_ports.get(p, {})
            ip_ports[p] = {
                "name": meta.get("name") or existing.get("name"),
                "product": meta.get("product") or existing.get("product"),
                "version": meta.get("version") or existing.get("version"),
                "extrainfo": meta.get("extrainfo") or existing.get("extrainfo"),
                "ostype": meta.get("ostype") or existing.get("ostype"),
            }

    return {
        "ok": True,
        "summary": {
            "hosts_found": hosts_found,
            "scanning_time": scanning_time,
            "finished_at": finished_at,
        },
        "port_map": port_map,
    }