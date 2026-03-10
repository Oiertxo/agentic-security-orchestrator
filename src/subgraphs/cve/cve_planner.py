from langchain_core.messages import AIMessage
from langchain_core.prompts import ChatPromptTemplate
from src.model import get_model
from src.state import AgentState, CveState, PlannerOutput
from src.schemas import PlannerSchema
from src.utils.utils import load_prompt
from src.utils.toon_formatter import port_map_to_toon, vulnerabilities_to_toon
from src.logger import logger
from typing import Dict, Any
from langfuse import observe
import json

@observe(name="CVE planner")
def cve_planner_node(state: AgentState) -> AgentState:
    llm = get_model()
    system_prompt = load_prompt("cve.txt")

    recon_state = state.get("recon", {})
    cve_state = state.get("cve", {})
    port_map = recon_state.get("port_map", {})
    last_result = cve_state.get("results", [])[-1:] if cve_state.get("results") else []

    logger.info(f"[CVE_PLANNER] State received: {state}")
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("system", "Port map (host: open ports): {port_map}"),
        ("system", "Pending services for CVE lookup: {pending_services_for_cve}"),
        ("system", "Result of last action: {last_result}"),
        ("system", "Vulnerabilities found: {vulnerabilities}")
    ])

    if not cve_state.get("pending_services_for_cve") \
        and not cve_state.get("analyzed_services_for_cve"):
        
        pending_cve = {}
        
        for ip, ports in port_map.items():
            pending_cve[ip] = list(ports.keys())
            
        cve_state["pending_services_for_cve"] = pending_cve
        cve_state["vulnerabilities"] = {}

    last_result = cve_state.get("results", [])[-1:] if cve_state.get("results") else []

    planner_input = {
        "port_map": port_map_to_toon(port_map),
        "pending_services_for_cve": cve_state.get("pending_services_for_cve", {}),
        "last_result": last_result,
        "vulnerabilities": vulnerabilities_to_toon(cve_state.get("vulnerabilities", {}))
    }

    logger.info(f"[CVE_PLANNER] Calling LLM with intel: {planner_input}")
    
    chain = (prompt | llm.with_structured_output(PlannerSchema, method="json_mode", strict=True)).with_types(
        input_type=Dict[str, Any],
        output_type=PlannerSchema,
    )

    try:
        result = PlannerSchema.model_validate(chain.invoke(planner_input))
        data = result.model_dump(mode="json")
    except Exception as e:
        logger.error(f"[CVE_PLANNER] Parsing error: {e}")
        data = {"finished": True, "next_tool": None, "arguments": {}}

    logger.info(f"[CVE_PLANNER] Response from LLM: {data}")
    
    if not data or (not data.get("finished") and not data.get("next_tool")):
        logger.error(f"[CVE_PLANNER] Planner failed to reason. Forcing termination")
        data = {
            "finished": True,
            "next_tool": None,
            "arguments": {},
        }

    is_finished = data.get("finished", False)
    new_planner: PlannerOutput = {
        "next_tool": data.get("next_tool", ""),
        "arguments": data.get("arguments", {}),
    }
    new_cve: CveState = {
        **cve_state,
        "planner": new_planner,
        "finished": is_finished,
    }

    return {
        **state,
        "cve": new_cve,
        "messages": state.get("messages") + [AIMessage(content=json.dumps(data))],
        "next_step": "supervisor" if is_finished else "executor"
    }