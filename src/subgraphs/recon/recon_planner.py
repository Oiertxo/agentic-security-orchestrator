from langchain_core.messages import AIMessage
from src.state import AgentState, ReconState, PlannerOutput
from src.model import get_model
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from src.utils import load_prompt, get_clean_content
from src.schemas import ReconPlannerSchema
from src.logger import logger
from typing import Dict, Any, cast
import json

def recon_planner_node(state: AgentState) -> AgentState:
    llm = get_model()
    RECON_AGENT_PROMPT = load_prompt("recon.txt")
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", RECON_AGENT_PROMPT),
        MessagesPlaceholder("messages"),
        ("human", "Port map (host → open ports): {port_map}"),
        ("human", "Already version-scanned hosts: {scanned_hosts}"),
        ("human", "Pending hosts for -sV: {pending_hosts}"),
    ])

    planner_input: Dict[str, Any] = {
        "messages": get_clean_content(state["messages"]),
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
    
    if not data or (not data.get("done") and not data.get("tool")):
        logger.error(f"[RECON_PLANNER] Planner failed to reason. Forcing termination")
        data = {
            "done": True,
            "tool": None,
            "arguments": {},
            "reason": "Forced finish: LLM returned empty or invalid plan after null results."
        }
    is_done = result.done

    new_recon: ReconState = {
        **state.get("recon", {}),
        "planner": cast(PlannerOutput, data),
        "done": is_done,
    }

    return {
        "messages": [AIMessage(content=json.dumps(data))],
        "recon": new_recon,
        "next_step": "supervisor" if is_done else "executor"
    }