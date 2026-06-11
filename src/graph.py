from langgraph.graph import END, StateGraph

from src.agents.cve_worker import cve_worker_node
from src.agents.exploit_worker import exploit_worker_node
from src.agents.recon_worker import recon_worker_node
from src.agents.report_worker import report_worker_node
from src.agents.supervisor import supervisor_node
from src.agents.vuln_map_worker import vuln_map_worker_node
from src.state import AgentState


def compile_workflow(checkpointer, interrupts_enabled: bool = True):
    workflow = StateGraph(AgentState)

    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("recon", recon_worker_node)
    workflow.add_node("cve", cve_worker_node)
    workflow.add_node("vuln_map", vuln_map_worker_node)
    workflow.add_node("exploit", exploit_worker_node)
    workflow.add_node("report", report_worker_node)

    workflow.set_entry_point("supervisor")

    workflow.add_conditional_edges(
        "supervisor",
        lambda x: x["next_step"],
        {
            "recon": "recon",
            "cve": "cve",
            "vuln_map": "vuln_map",
            "exploit": "exploit",
            "report": "report",
            "finish": END,
        },
    )

    workflow.add_edge("recon", "supervisor")
    workflow.add_edge("cve", "supervisor")
    workflow.add_edge("vuln_map", "supervisor")
    workflow.add_edge("exploit", "supervisor")
    workflow.add_edge("report", "supervisor")

    compile_kwargs = {"checkpointer": checkpointer}

    if interrupts_enabled:
        compile_kwargs["interrupt_before"] = [
            "recon",
            "cve",
            "vuln_map",
            "exploit",
        ]

    return workflow.compile(**compile_kwargs)
