from langgraph.graph import StateGraph, END
from .state import ReconState
from .planner_node import recon_planner_node
from .executor_node import recon_executor_node
from src.logger import logger

MAX_STEPS = 20

def build_recon_subgraph():
    graph = StateGraph(ReconState)

    graph.add_node("planner", recon_planner_node)
    graph.add_node("executor", recon_executor_node)

    graph.set_entry_point("planner")

    def route_from_planner(state: ReconState):
        step = int(state.get("step_count", 0))
        
        if state.get("done") or step >= MAX_STEPS:
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