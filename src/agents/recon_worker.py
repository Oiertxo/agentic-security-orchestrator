from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from src.state import AgentState, ReconState
from src.subgraphs.recon.recon_subgraph import recon_subgraph
from src.logger import logger
from langfuse import observe

@observe(name="Recon Worker")
async def recon_worker_node(state: AgentState, config: RunnableConfig) -> AgentState:
    old_recon = state.get("recon", {})
    out = await recon_subgraph.ainvoke(state, config)
    logger.info(f"[RECON_WORKER_NODE] Output: {out}")
    
    recon_out: ReconState = out.get("recon", {})
    recon_out["finished"] = bool(recon_out.get("finished", False))
    executive_summary = (
        f"[PHASE COMPLETE] Execution finished in {recon_out.get("step_count", 0)} steps. "
        f"Identified {len(recon_out.get("scanned_hosts", []))} active hosts with {len(recon_out.get("port_map", {}))} services."
    )
    recon_out.get("results", []).append({"final_result": executive_summary})

    return {
        "user_target": state.get("user_target"),
        "next_step": "supervisor",
        "recon": {
            **old_recon,
            **recon_out
        },
        "messages": state["messages"] + [HumanMessage(content=f"[SOURCE: RECON]\n{executive_summary}")]
    }