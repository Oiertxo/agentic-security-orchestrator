import json
from typing import Optional, Tuple

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
    vuln_map_state = state.get("vuln_map", {})

    logger.info("[VULN_MAP_PLANNER] Entering Vuln map planner")

    pending: dict[str, dict[int, list[str]]] = vuln_map_state.get(
        "pending_services_for_search", {}
    )
    analyzed: dict[str, dict[int, list[str]]] = vuln_map_state.get(
        "analyzed_services_for_search", {}
    )

    # Move CVE-less services to analyzed
    for ip in list(pending.keys()):
        for port in list(pending[ip].keys()):
            if not pending[ip][port]:
                analyzed.setdefault(ip, {}).setdefault(port, [])
                pending[ip].pop(port)
        if not pending[ip]:
            pending.pop(ip)

    # Finish if nothing pending
    if not pending:
        found_exploits = vuln_map_state.get("found_exploits", {})
        for _, entry in found_exploits.items():
            for exp in entry.get("exploits", []):
                path_in_kali = exp.get("path")
                edb_id = exp.get("edb_id")
                if not path_in_kali or not edb_id:
                    continue
                local_path = save_exploit_locally(path_in_kali, edb_id)
                if local_path:
                    exp["local_path"] = local_path

        return {
            **state,
            "vuln_map": {
                **vuln_map_state,
                "pending_services_for_search": pending,
                "analyzed_services_for_search": analyzed,
                "planner": {"next_tool": None, "arguments": {}},
                "finished": True,
            },
            "messages": state.get("messages", [])
            + [AIMessage(content=json.dumps({"finished": True}))],
            "next_step": "supervisor",
        }

    # Select next pending service
    selection = pick_next_cve(pending)

    if selection is None:
        return {
            **state,
            "vuln_map": {
                **vuln_map_state,
                "pending_services_for_search": pending,
                "analyzed_services_for_search": analyzed,
                "planner": {"next_tool": None, "arguments": {}},
                "finished": True,
            },
            "next_step": "supervisor",
        }

    next_ip, next_port, next_cve = selection

    # Move CVE to analyzed
    analyzed.setdefault(next_ip, {}).setdefault(next_port, []).append(next_cve)

    if not pending[next_ip][next_port]:
        pending[next_ip].pop(next_port)
    if not pending[next_ip]:
        pending.pop(next_ip)

    # Exploit lookup plan
    service = port_map.get(next_ip, {}).get(next_port, {})
    product = service.get("product")
    version = service.get("version")

    planner_output: PlannerOutput = {
        "next_tool": "search_exploit",
        "arguments": {
            "target": next_ip,
            "product": product,
            "version": normalize_version(version),
            "port": next_port,
            "cve": next_cve,
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


def pick_next_cve(
    pending: dict[str, dict[int, list[str]]],
) -> Optional[Tuple[str, int, str]]:
    for ip, ports in pending.items():
        for port, cves in ports.items():
            if cves:
                return ip, port, cves.pop(0)
    return None
