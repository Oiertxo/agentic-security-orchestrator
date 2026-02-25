from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from src.state import AgentState, ReconState
from src.subgraphs.recon.recon_subgraph import recon_subgraph
from src.logger import logger
from langfuse import observe

@observe(name="Recon Worker")
def recon_worker_node(state: AgentState, config: RunnableConfig) -> AgentState:
    old_recon = state.get("recon") or {}
    out = recon_subgraph.invoke(state, config)
    logger.info(f"[RECON_WORKER_NODE] Output: {out}")
    
    recon_out: ReconState = out.get("recon") or {}
    recon_out["finished"] = bool(recon_out.get("finished", False))
    summary = {
        "steps": recon_out.get("step_count", 0),
        "results": recon_out.get("results", ["Recon not available"]),
    }

    return {
        "user_target": state.get("user_target"),
        "next_step": "supervisor",
        "recon": {
            **old_recon,
            **recon_out
        },
        "messages": state["messages"] + [HumanMessage(content=f"[SOURCE: RECON]\n{summary}")]
    }