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

    logger.info("[CVE_PLANNER] Entering CVE planner")

    # Initialization
    if pending is None:
        pending = {ip: list(ports.keys()) for ip, ports in port_map.items() if ports}
        cve_state["pending_services_for_cve"] = pending
        cve_state.setdefault("vulnerabilities", {})
        cve_state.setdefault("analyzed_services_for_cve", {})
        cve_state.setdefault("skipped_services_for_cve", {})

    analyzed = cve_state.get("analyzed_services_for_cve", {})
    skipped = cve_state.get("skipped_services_for_cve", {})

    # MAIN LOOP
    while pending:
        ip = next(iter(pending))
        port = pending[ip].pop(0)

        # bookkeeping
        analyzed.setdefault(ip, []).append(int(port))
        if not pending[ip]:
            pending.pop(ip)

        service = port_map.get(ip, {}).get(port, {})
        name = service.get("name")
        product = service.get("product")
        version = service.get("version")
        app_name = service.get("app_name")
        app_version = service.get("app_version")

        # Not CVE-eligible: skip and continue loop
        if not isinstance(product, str) or not product.strip():
            logger.info(
                f"[CVE_PLANNER] Skipping {ip}:{port} — insufficient fingerprint"
            )
            skipped.setdefault(ip, []).append(int(port))
            continue

        # CVE-eligible: plan lookup
        logger.info(
            f"[CVE_PLANNER] Selected {ip}:{port} ({name} {product} {version} {app_name} {app_version}) for CVE lookup"
        )

        planner_output: PlannerOutput = {
            "next_tool": "cve_lookup",
            "arguments": {
                "target": ip,
                "name": name,
                "product": product,
                "version": normalize_version(version),
                "app_name": app_name,
                "app_version": normalize_version(app_version),
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
                "skipped_services_for_cve": skipped,
                "planner": planner_output,
                "finished": False,
            },
            "messages": state.get("messages", [])
            + [AIMessage(content=json.dumps(planner_output))],
            "next_step": "executor",
        }

    # No pending services left
    logger.info("[CVE_PLANNER] No CVE-eligible services remaining. Finishing CVE phase")

    return {
        **state,
        "cve": {
            **cve_state,
            "pending_services_for_cve": {},
            "analyzed_services_for_cve": analyzed,
            "skipped_services_for_cve": skipped,
            "planner": {"next_tool": None, "arguments": {}},
            "finished": True,
        },
        "messages": state.get("messages", [])
        + [AIMessage(content=json.dumps({"finished": True}))],
        "next_step": "supervisor",
    }
