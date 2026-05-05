from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.state import AgentState, VulnMapState
from src.subgraphs.vuln_map.vuln_map_subgraph import vuln_map_subgraph


@observe(name="Vuln Map Worker")
async def vuln_map_worker_node(state: AgentState, config: RunnableConfig) -> AgentState:
    old_vuln_map = state.get("vuln_map", {})
    cve_state = state.get("cve", {})

    if "pending_cves_for_search" not in old_vuln_map:
        pending = {}
        analyzed = {}

        raw_vulns = cve_state.get("vulnerabilities", {})

        for service_key, cves in raw_vulns.items():
            ip, port_str = service_key.split(":")
            port = int(port_str)

            pending.setdefault(ip, {}).setdefault(port, [])
            analyzed.setdefault(ip, {}).setdefault(port, [])

            for c in cves:
                cve_id = c.get("cve_id")
                if cve_id:
                    pending[ip][port].append(cve_id)

        state = {
            **state,
            "vuln_map": {
                **old_vuln_map,
                "pending_services_for_search": pending,
                "analyzed_services_for_search": analyzed,
                "step_count": 0,
                "found_exploits": {},
            },
        }
    out = await vuln_map_subgraph.ainvoke(state, config)
    logger.info(f"[VULN_MAP_WORKER_NODE] Output: {out}")

    vuln_map_out: VulnMapState = out.get("vuln_map", {})
    vuln_map_out["finished"] = bool(vuln_map_out.get("finished", False))
    steps = vuln_map_out.get("step_count", 0)
    found_exploits = sum(
        len(v.get("exploits", [])) + len(v.get("framework_modules", []))
        for v in vuln_map_out.get("found_exploits", {}).values()
        if isinstance(v, dict)
    )

    executive_summary = (
        f"[PHASE COMPLETE] Execution finished in {steps} steps. "
        f"Identified {found_exploits} exploit scripts."
    )
    vuln_map_out.get("results", []).append({"final_result": executive_summary})

    return {
        **state,
        "user_target": state.get("user_target"),
        "vuln_map": {**old_vuln_map, **vuln_map_out},
        "messages": state["messages"]
        + [HumanMessage(content=f"[SOURCE: VULN_MAP]\n{executive_summary}")],
        "next_step": "supervisor",
    }
