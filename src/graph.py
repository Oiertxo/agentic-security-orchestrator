from langgraph.graph import StateGraph, END
from src.state import AgentState
from src.agents.supervisor import supervisor_node
from src.agents.recon_worker import recon_worker_node
from src.agents.exploit_worker import exploit_worker_node
from src.agents.report_worker import report_worker_node

def compile_workflow():
    workflow = StateGraph(AgentState)
    
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("recon", recon_worker_node)
    workflow.add_node("exploit", exploit_worker_node)
    workflow.add_node("report", report_worker_node)
    
    workflow.set_entry_point("supervisor")
    
    workflow.add_conditional_edges(
        "supervisor",
        lambda x: x["next_step"],
        {
            "recon": "recon",
            "exploit": "exploit",
            "report": "report",
            "finish": END
        }
    )
    
    workflow.add_edge("recon", "supervisor")
    workflow.add_edge("exploit", "supervisor")
    workflow.add_edge("report", "supervisor")
    
    return workflow.compile()