from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from src.state import AgentState, ReconState
# from src.subgraphs.cve.cve_subgraph import cve_subgraph
from src.logger import logger
from langfuse import observe

@observe(name="Recon Worker")
def cve_worker_node(state: AgentState, config: RunnableConfig) -> AgentState:
    # old_recon = state.get("recon") or {}
    # out = cve_subgraph.invoke(state, config)
    # logger.info(f"[CVE_WORKER_NODE] Output: {out}")
    
    # recon_out: ReconState = out.get("recon") or {}
    # recon_out["finished"] = bool(recon_out.get("finished", False))
    # summary = {
    #     "steps": recon_out.get("step_count", 0),
    #     "results": recon_out.get("results", ["CVE search not available"]),
    # }

    # return {
    #     "user_target": state.get("user_target"),
    #     "next_step": "supervisor",
    #     "recon": {
    #         **old_recon,
    #         **recon_out
    #     },
    #     "messages": state["messages"] + [HumanMessage(content=f"[SOURCE: CVE]\n{summary}")]
    # }
    return state