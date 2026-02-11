from langchain_core.messages import AIMessage
from src.state import AgentState
from src.subgraphs.recon.subgraph import recon_subgraph

def recon_worker_node(state: AgentState):
    out = recon_subgraph.invoke({
        "messages": state["messages"],
        "results": [],
        "step_count": 0,
        "done": False
    })
    summary = {
        "steps": out.get("step_count", 0),
        "results": out.get("results", ["Recon not available"])
    }
    return {
        "messages": [AIMessage(content=f"[SOURCE: RECON]\n{summary}")],
        "next_step": "supervisor"
    }