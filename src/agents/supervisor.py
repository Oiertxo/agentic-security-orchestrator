from langchain_core.messages import AIMessage
from src.state import AgentState
from src.model import get_model
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from src.utils import load_prompt
from src.utils import get_clean_content
from src.schemas import SupervisorSchema
from src.logger import logger
from typing import Dict, Any

def supervisor_node(state: AgentState) -> AgentState:
    llm = get_model()
    system_prompt = load_prompt("supervisor.txt")

    recon_ns = state.get("recon", {}) or {}
    exploit_ns = state.get("exploit", {}) or {}

    supervisor_input = {
        "messages": get_clean_content(state["messages"])
    }

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        MessagesPlaceholder("messages")
    ])

    logger.info(f"[SUPERVISOR] Invoking Worker Planner. Input: {supervisor_input}")
    
    chain = (
        prompt
        | llm.with_structured_output(SupervisorSchema, method="json_mode", strict=True)
    ).with_types(
        input_type=Dict[str, Any],
        output_type=SupervisorSchema,
    )

    response: SupervisorSchema = SupervisorSchema.model_validate(chain.invoke(supervisor_input))

    logger.info(f"[SUPERVISOR] Worker Planner response: {response}")

    return {
        "messages": [AIMessage(content=response.message)],
        "next_step": response.next_step
    }