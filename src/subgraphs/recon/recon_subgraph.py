from langfuse import observe
from langgraph.graph import END, StateGraph

from src.state import AgentState

from .recon_executor import recon_executor_node
from .recon_planner import recon_planner_node

MAX_STEPS = 40


@observe(name="Recon subgraph")
def build_recon_subgraph():
    graph = StateGraph(AgentState)

    graph.add_node("recon_planner", recon_planner_node)
    graph.add_node("recon_executor", recon_executor_node)

    graph.set_entry_point("recon_planner")

    def route_from_planner(state: AgentState):
        step = int((state.get("recon", {})).get("step_count", 0))
        finished = (state.get("recon", {})).get("finished", False)
        if finished or step >= MAX_STEPS:
            return "finish"
        return "recon_executor"

    graph.add_conditional_edges(
        "recon_planner",
        route_from_planner,
        {
            "finish": END,
            "recon_executor": "recon_executor",
        },
    )

    graph.add_edge("recon_executor", "recon_planner")

    return graph.compile()


recon_subgraph = build_recon_subgraph()
