import json

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.state import AgentState, PlannerOutput
from src.utils.exploit_reader import save_exploit_locally
from src.utils.utils import normalize_version


@observe(name="Vuln Map planner")
async def vuln_map_planner_node(
    state: AgentState, config: RunnableConfig
) -> AgentState:
    recon_state = state.get("recon", {})
    port_map = recon_state.get("port_map", {})
    cve_state = state.get("cve", {})
    vuln_map_state = state.get("vuln_map", {})

    logger.info(f"[VULN_MAP_PLANNER] State received: {state}")

    if "pending_services_for_search" not in vuln_map_state:
        pending = {}
        for ip, ports in port_map.items():
            pending[ip] = [{"port": port} for port in ports.keys()]
        vuln_map_state["pending_services_for_search"] = pending

    pending = vuln_map_state.get("pending_services_for_search", {})
    analyzed = vuln_map_state.get("analyzed_services_for_search", {})

    # End if nothing pending
    if not pending or all(len(services) == 0 for services in pending.values()):
        found_exploits = vuln_map_state.get("found_exploits", {})
        for _, exploits in found_exploits.items():
            for exp in exploits:
                path_in_kali = exp.get("path", "")
                edb_id = exp.get("edb_id", "")

                local_path = save_exploit_locally(path_in_kali, edb_id)
                if local_path:
                    exp["local_path"] = local_path
        return {
            **state,
            "vuln_map": {
                **vuln_map_state,
                "planner": {"next_tool": None, "arguments": {}},
                "finished": True,
            },
            "messages": state.get("messages", [])
            + [AIMessage(content=json.dumps({"finished": True}))],
            "next_step": "supervisor",
        }

    ip = next(iter(pending.keys()))
    pending_service = pending[ip].pop(0)
    port = int(pending_service["port"])

    ports = analyzed.setdefault(ip, [])
    ports.append(port)

    if not pending[ip]:
        pending.pop(ip)

    service = port_map.get(ip, {}).get(port, {})
    product = service.get("product")
    version = service.get("version")

    cve_key = f"{ip}:{port}"
    cves = cve_state.get("vulnerabilities", {}).get(cve_key)
    selected_cve = cves[0]["cve_id"] if cves else None

    planner_output: PlannerOutput = {
        "next_tool": "search_exploit",
        "arguments": {
            "target": ip,
            "product": product,
            "version": normalize_version(version),
            "port": port,
            "cve": selected_cve,
        },
    }

    return {
        **state,
        "vuln_map": {
            **vuln_map_state,
            "pending_services_for_search": pending,
            "analyzed_services_for_search": analyzed,
            "planner": planner_output,
            "finished": False,
        },
        "messages": state.get("messages", [])
        + [AIMessage(content=json.dumps(planner_output))],
        "next_step": "executor",
    }
