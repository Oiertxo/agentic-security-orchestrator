from langfuse import observe
from langgraph.graph import END, StateGraph

from src.state import AgentState

from .vuln_map_executor import vuln_map_executor_node
from .vuln_map_planner import vuln_map_planner_node

MAX_STEPS = 40


@observe(name="Vuln Map subgraph")
def build_vuln_map_subgraph():
    graph = StateGraph(AgentState)

    graph.add_node("planner", vuln_map_planner_node)
    graph.add_node("executor", vuln_map_executor_node)

    graph.set_entry_point("planner")

    def route_from_planner(state: AgentState):
        step = int((state.get("vuln_map", {})).get("step_count", 0))
        finished = (state.get("vuln_map", {})).get("finished", False)
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


vuln_map_subgraph = build_vuln_map_subgraph()
