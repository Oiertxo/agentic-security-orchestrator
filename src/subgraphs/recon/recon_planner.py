from langchain_core.messages import AIMessage
from src.state import AgentState, ReconState, PlannerOutput
from src.model import get_model
from langchain_core.prompts import ChatPromptTemplate
from src.utils import load_prompt
from src.schemas import ReconPlannerSchema
from src.logger import logger
from typing import Dict, Any, cast
from langfuse import observe
import json

@observe(name="Recon planner")
def recon_planner_node(state: AgentState) -> AgentState:
    llm = get_model()
    system_prompt = load_prompt("recon.txt")
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("system", "Target requested by the user: {user_target}"),
        ("system", "Port map (host and their open ports): {port_map}"),
        ("system", "Already version-scanned hosts: {scanned_hosts}"),
        ("system", "Pending hosts for -sV: {pending_hosts}"),
    ])

    planner_input: Dict[str, Any] = {
        "user_target": state.get("user_target"),
        "port_map": (state.get("recon", {}) or {}).get("port_map", {}),
        "scanned_hosts": (state.get("recon", {}) or {}).get("scanned_hosts", []),
        "pending_hosts": (state.get("recon", {}) or {}).get("pending_hosts", []),
    }

    logger.info(f"[RECON_PLANNER] Calling LLM: {planner_input}")
    
    chain = (prompt | llm.with_structured_output(ReconPlannerSchema, method="json_mode", strict=True)).with_types(
        input_type=Dict[str, Any],
        output_type=ReconPlannerSchema,
    )

    result = ReconPlannerSchema.model_validate(chain.invoke(planner_input))
    data = result.model_dump(mode="json")
    
    logger.info(f"[RECON_PLANNER] Response from LLM: {data}")
    
    if not data or (not data.get("finished") and not data.get("next_tool")):
        logger.error(f"[RECON_PLANNER] Planner failed to reason. Forcing termination")
        data = {
            "finished": True,
            "next_tool": None,
            "arguments": {},
            "reason": "Forced finish: LLM returned empty or invalid plan after null results."
        }
    is_finished = result.finished
    new_planner: PlannerOutput = {
        "next_tool": data.get("next_tool", ""),
        "arguments": data.get("arguments", {}),
    }
    new_recon: ReconState = {
        **state.get("recon", {}),
        "planner": new_planner,
        "finished": is_finished,
    }

    return {
        **state,
        "recon": new_recon,
        "messages": state.get("messages") + [AIMessage(content=json.dumps(data))],
        "next_step": "supervisor" if is_finished else "executor"
    }