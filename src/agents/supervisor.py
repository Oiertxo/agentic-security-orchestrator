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
    SUPERVISOR_INSTRUCTIONS = load_prompt("supervisor.txt")

    clean_messages = get_clean_content(state["messages"])
    
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", SUPERVISOR_INSTRUCTIONS),
        MessagesPlaceholder(variable_name="messages"),
    ])
    logger.info(f"[SUPERVISOR] Invoking Worker Planner. Messages: {clean_messages}")    
    
    chain = (prompt_template | llm.with_structured_output(SupervisorSchema)).with_types(
        input_type=Dict[str, Any],
        output_type=SupervisorSchema,
    )
    response = SupervisorSchema.model_validate(chain.invoke({"messages": clean_messages}))

    logger.info(f"[SUPERVISOR] Worker Planner response: {response}")

    return AgentState(
        messages=[AIMessage(content=response.message)],
        next_step=response.next_step
    )