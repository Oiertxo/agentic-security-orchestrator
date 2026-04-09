from langfuse import observe
from langgraph.graph import END, StateGraph

from src.state import AgentState

from .cve_executor import cve_executor_node
from .cve_planner import cve_planner_node

MAX_STEPS = 40


@observe(name="CV subgraph")
def build_cve_subgraph():
    graph = StateGraph(AgentState)

    graph.add_node("planner", cve_planner_node)
    graph.add_node("executor", cve_executor_node)

    graph.set_entry_point("planner")

    def route_from_planner(state: AgentState):
        step = int((state.get("cve", {})).get("step_count", 0))
        finished = (state.get("cve", {})).get("finished", False)
        if finished or step >= MAX_STEPS:
            return "finish"
        return "executor"

    graph.add_conditional_edges(
        "planner",
        route_from_planner,
        {
            "finish": END,
            "executor": "executor",
        },
    )

    graph.add_edge("executor", "planner")

    return graph.compile()


cve_subgraph = build_cve_subgraph()
