from langchain_core.messages import AIMessage
from src.subgraphs.recon.state import ReconState
from src.model import get_model
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from src.utils import load_prompt, get_clean_content
from src.subgraphs.recon.schemas import PlannerSchema
from src.logger import logger
from typing import Dict, Any
import json

def recon_planner_node(state: ReconState):
    llm = get_model()
    RECON_AGENT_PROMPT = load_prompt("recon.txt")
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", RECON_AGENT_PROMPT),
        MessagesPlaceholder("messages"),
        ("human", "Port map (host → open ports): {port_map}"),
        ("human", "Already version-scanned hosts: {scanned_hosts}"),
        ("human", "Pending hosts for -sV: {pending_hosts}"),
    ])


    clean_messages = get_clean_content(state["messages"])
    
    variables = {
        "messages": clean_messages,
        "port_map": state.get("port_map") or {},
        "scanned_hosts": state.get("scanned_hosts") or [],
        "pending_hosts": state.get("pending_hosts") or [],
    }

    logger.info(f"[RECON_PLANNER] Calling LLM: {variables}")
    
    chain = (prompt | llm.with_structured_output(PlannerSchema, method="json_mode", strict=True)).with_types(
        input_type=Dict[str, Any],
        output_type=PlannerSchema,
    )

    result = PlannerSchema.model_validate(chain.invoke(variables))
    data = result.model_dump(mode="json")
    
    logger.info(f"[RECON_PLANNER] Response from LLM: {data}")
    
    if not data or (not data.get("done") and not data.get("tool")):
        logger.error(f"[RECON_PLANNER] Planner failed to reason. Forcing termination")
        data = {
            "action": "finish",
            "done": True,
            "tool": None,
            "arguments": {},
            "reason": "Forced finish: LLM returned empty or invalid plan after null results."
        }
    is_done = result.done

    return {
        "messages": [AIMessage(content=json.dumps(data))],
        "done": is_done
    }