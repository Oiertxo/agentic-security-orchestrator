from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.state import AgentState, CveState
from src.subgraphs.cve.cve_subgraph import cve_subgraph


@observe(name="CVE Worker")
async def cve_worker_node(state: AgentState, config: RunnableConfig) -> AgentState:
    old_cve = state.get("cve", {})
    out = await cve_subgraph.ainvoke(state, config)
    logger.info(f"[CVE_WORKER_NODE] Output: {out}")

    cve_out: CveState = out.get("cve", {})
    cve_out["finished"] = bool(cve_out.get("finished", False))

    # Intended cve if not found for Vulhub testing
    intended_cve = state.get("intended_cve")
    if intended_cve:
        port_map = state.get("recon", {}).get("port_map", {})
        ip = intended_cve.get("target_ip")
        port = intended_cve.get("target_port")

        if not ip or ip not in port_map or port not in port_map.get(ip, {}):
            logger.warning(
                f"[CVE_WORKER_NODE] Invalid target surface for intended CVE: {ip}:{port}, skipping injection"
            )
        else:
            target_surface = f"{ip}:{port}"
            new_intended_cve = intended_cve["cve"]
            vulnerabilities = cve_out.setdefault("vulnerabilities", {})
            existing_cves = vulnerabilities.get(target_surface, [])

            already_present = any(
                cve.get("cve_id") == new_intended_cve["cve_id"] for cve in existing_cves
            )

            if already_present:
                logger.info(
                    f"[CVE_WORKER_NODE] Intended CVE {new_intended_cve['cve_id']} already present in {target_surface}, skipping injection"
                )
            else:
                new_intended_cve = intended_cve["cve"]
                vulnerabilities.setdefault(target_surface, []).append(new_intended_cve)

                logger.info(
                    f"[CVE_WORKER_NODE] Injected {new_intended_cve['cve_id']} into {target_surface}"
                )

    steps = cve_out.get("step_count", 0)
    found_cves = len(cve_out.get("vulnerabilities", {}))
    executive_summary = (
        f"[PHASE COMPLETE] Execution finished in {steps} steps. "
        f"Identified {found_cves} services with CVEs."
    )
    cve_out.get("results", []).append({"final_result": executive_summary})

    return {
        **state,
        "user_target": state.get("user_target"),
        "next_step": "supervisor",
        "cve": {**old_cve, **cve_out},
        "messages": state["messages"]
        + [HumanMessage(content=f"[SOURCE: CVE]\n{executive_summary}")],
    }
