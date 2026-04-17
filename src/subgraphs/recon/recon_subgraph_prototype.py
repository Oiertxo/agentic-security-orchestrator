from langfuse import observe
from langgraph.graph import END, StateGraph

from src.state import AgentState

from .recon_executor import recon_executor_node
from .recon_planner import recon_planner_node

MAX_STEPS = 40


def has_web_service(state: AgentState) -> bool:
    port_map = (state.get("recon", {}) or {}).get("port_map", {})

    for host_services in port_map.values():
        for service_meta in host_services.values():
            name = (service_meta or {}).get("name", "")
            if name in ("http", "https"):
                return True
    return False


@observe(name="Recon subgraph")
def build_recon_subgraph():
    graph = StateGraph(AgentState)

    graph.add_node("planner", recon_planner_node)
    graph.add_node("executor", recon_executor_node)
    graph.add_node("web_recon", web_recon_node)

    graph.set_entry_point("planner")

    def route_from_planner(state: AgentState):
        recon = state.get("recon", {}) or {}
        step = int(recon.get("step_count", 0))
        finished = recon.get("finished", False)

        if finished or step >= MAX_STEPS:
            return "finish"

        if has_web_service(state) and not recon.get("web_intel"):
            return "web_recon"

        return "executor"

    graph.add_conditional_edges(
        "planner",
        route_from_planner,
        {
            "finish": END,
            "executor": "executor",
            "web_recon": "web_recon",
        },
    )

    graph.add_edge("executor", "planner")
    graph.add_edge("web_recon", END)

    return graph.compile()


recon_subgraph = build_recon_subgraph()
