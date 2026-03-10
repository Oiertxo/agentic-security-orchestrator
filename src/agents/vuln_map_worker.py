from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from src.state import AgentState, VulnMapState
from src.subgraphs.vuln_map.vuln_map_subgraph import vuln_map_subgraph
from src.logger import logger
from langfuse import observe

@observe(name="Vuln Map Worker")
def vuln_map_worker_node(state: AgentState, config: RunnableConfig) -> AgentState:
    old_vuln_map = state.get("vuln_map", {})
    out = vuln_map_subgraph.invoke(state, config)
    logger.info(f"[VULN_MAP_WORKER_NODE] Output: {out}")
    
    vuln_map_out: VulnMapState = out.get("vuln_map", {})
    vuln_map_out["finished"] = bool(vuln_map_out.get("finished", False))
    steps = vuln_map_out.get("step_count", 0)
    found_exploits = sum(len(exps) for exps in vuln_map_out.get("found_exploits", {}).values()) if isinstance(vuln_map_out.get("found_exploits"), dict) else 0

    executive_summary = (
        f"[PHASE COMPLETE] Execution finished in {steps} steps. "
        f"Identified {found_exploits} exploit scripts."
    )
    vuln_map_out.get("results", []).append({"final_result": executive_summary})

    return {
        "user_target": state.get("user_target"),
        "vuln_map": {
            **old_vuln_map,
            **vuln_map_out
        },
        "messages": state["messages"] + [HumanMessage(content=f"[SOURCE: VULN_MAP]\n{executive_summary}")],
        "next_step": "supervisor"
    }