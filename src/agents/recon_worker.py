from langchain_core.messages import AIMessage
from src.state import AgentState
from src.subgraphs.recon.recon_subgraph import recon_subgraph
from src.logger import logger

def recon_worker_node(state: AgentState) -> AgentState:
    out = recon_subgraph.invoke(state)
    logger.info(f"[RECON_WORKER_NODE] Output: {out}")
    
    recon_out = out.get("recon") or {}
    summary = {
        "steps": recon_out.get("step_count", 0),
        "results": recon_out.get("results", ["Recon not available"]),
    }

    return {
        "messages": [AIMessage(content=f"[SOURCE: RECON]\n{summary}")],
        "next_step": "supervisor",
        "recon": {
            "port_map": (out.get("recon") or {}).get("port_map") or {},
            "results": (out.get("recon") or {}).get("results") or [],
            "scanned_hosts": (out.get("recon") or {}).get("scanned_hosts") or []
        }
    }