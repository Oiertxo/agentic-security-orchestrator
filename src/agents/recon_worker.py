from langchain_core.messages import AIMessage
from src.state import AgentState
from src.subgraphs.recon.recon_subgraph import recon_subgraph
from src.subgraphs.recon.recon_state import ReconState

def recon_worker_node(state: AgentState):
    initial_recon_state: ReconState = {
        "messages": state["messages"],
        "results": [],
        "port_map": {},
        "scanned_hosts": [],
        "pending_hosts": [],
        "done": False,
        "step_count": 0,
    }

    out = recon_subgraph.invoke(initial_recon_state)

    summary = {
        "steps": out.get("step_count", 0),
        "results": out.get("results", ["Recon not available"])
    }
    return {
        "messages": [AIMessage(content=f"[SOURCE: RECON]\n{summary}")],
        "next_step": "supervisor"
    }