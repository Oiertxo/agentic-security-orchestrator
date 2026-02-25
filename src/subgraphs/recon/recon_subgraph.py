from langgraph.graph import StateGraph, END
from src.state import AgentState
from .recon_planner import recon_planner_node
from .recon_executor import recon_executor_node
from src.logger import logger
from langfuse import observe

MAX_STEPS = 20

@observe(name="Recon subgraph")
def build_recon_subgraph():
    graph = StateGraph(AgentState)

    graph.add_node("planner", recon_planner_node)
    graph.add_node("executor", recon_executor_node)

    graph.set_entry_point("planner")

    def route_from_planner(state: AgentState):
        step = int((state.get("recon", {}) or {}).get("step_count", 0))
        finished = (state.get("recon", {}) or {}).get("finished", False)
        if finished or step >= MAX_STEPS:
            return "finish"
        return "executor"

    graph.add_conditional_edges(
        "planner",
        route_from_planner,
        {
            "finish": END,
            "executor": "executor",
        }
    )

    graph.add_edge("executor", "planner")

    return graph.compile()

recon_subgraph = build_recon_subgraph()