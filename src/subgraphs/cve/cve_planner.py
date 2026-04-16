import json

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.state import AgentState, PlannerOutput
from src.utils.utils import normalize_version


@observe(name="CVE planner")
async def cve_planner_node(state: AgentState, config: RunnableConfig) -> AgentState:
    recon_state = state.get("recon", {})
    cve_state = state.get("cve", {})
    port_map = recon_state.get("port_map", {})
    pending = cve_state.get("pending_services_for_cve")

    logger.info(f"[CVE_PLANNER] State received: {state}")

    # Initialization
    if "pending_services_for_cve" not in cve_state:
        pending = {ip: list(ports.keys()) for ip, ports in port_map.items() if ports}
        cve_state["pending_services_for_cve"] = pending
        cve_state.setdefault("vulnerabilities", {})

    # Termination
    if not pending or all(len(ports) == 0 for ports in pending.values()):
        logger.info("[CVE_PLANNER] No pending services. Finishing CVE phase")
        return {
            **state,
            "cve": {
                **cve_state,
                "planner": {"next_tool": None, "arguments": {}},
                "finished": True,
            },
            "messages": state.get("messages", [])
            + [AIMessage(content=json.dumps({"finished": True}))],
            "next_step": "supervisor",
        }

    ip = next(iter(pending.keys()))
    port = pending[ip].pop(0)

    # Cleanse
    analyzed = cve_state.get("analyzed_services_for_cve", {})
    ports = analyzed.setdefault(ip, [])
    ports.append(int(port))
    if not pending[ip]:
        pending.pop(ip)

    service = port_map.get(ip, {}).get(port, {})

    product = service.get("product")
    version = service.get("version")

    logger.info(
        f"[CVE_PLANNER] Selected {ip}:{port} ({product} {version}) for CVE lookup"
    )

    planner_output: PlannerOutput = {
        "next_tool": "cve_lookup",
        "arguments": {
            "target": ip,
            "product": product,
            "version": normalize_version(version),
            "port": int(port),
            "cve": None,
        },
    }

    return {
        **state,
        "cve": {
            **cve_state,
            "pending_services_for_cve": pending,
            "analyzed_services_for_cve": analyzed,
            "planner": planner_output,
            "finished": False,
        },
        "messages": state.get("messages", [])
        + [AIMessage(content=json.dumps(planner_output))],
        "next_step": "executor",
    }
