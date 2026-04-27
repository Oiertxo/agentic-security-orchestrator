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
