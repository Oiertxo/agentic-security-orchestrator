from langgraph.graph import StateGraph, END
from src.state import AgentState
from src.agents.supervisor import supervisor_node
from src.agents.worker import mock_worker_node

def compile_workflow():
    workflow = StateGraph(AgentState)
    
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("worker", mock_worker_node)
    
    workflow.set_entry_point("supervisor")
    
    workflow.add_conditional_edges(
        "supervisor",
        lambda x: x["next_step"],
        {
            "worker": "worker",
            "FINISH": END
        }
    )
    
    workflow.add_edge("worker", "supervisor")
    
    return workflow.compile()