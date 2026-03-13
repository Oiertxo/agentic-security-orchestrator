from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableConfig
from src.state import AgentState
from src.model import get_model
from src.utils.utils import load_prompt, supervisor_state_view
from src.schemas import SupervisorSchema
from src.logger import logger
from typing import Dict, Any
from langfuse import observe

@observe(name="Supervisor node")
async def supervisor_node(state: AgentState, config: RunnableConfig) -> AgentState:
    llm = get_model()
    system_prompt = load_prompt("supervisor.txt")

    supervisor_input = {
        "state": supervisor_state_view(state)
    }

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("system", "Current State of execution:\n{state}"),
    ])

    logger.info(f"[SUPERVISOR] Received state: {state}")
    logger.info(f"[SUPERVISOR] Invoking Supervisor Planner. Input: {supervisor_input}")
    
    chain = (
        prompt
        | llm.with_structured_output(SupervisorSchema, method="json_mode", strict=True)
    ).with_types(
        input_type=Dict[str, Any],
        output_type=SupervisorSchema,
    )

    raw_response = await chain.ainvoke(supervisor_input, config=config)
    response: SupervisorSchema = SupervisorSchema.model_validate(raw_response)

    logger.info(f"[SUPERVISOR] Supervisor Planner response: {response}")
    
    return {
        **state,
        "user_target": response.user_target,
        "messages": [state["messages"][0], AIMessage(content=response.message)],
        "next_step": response.next_step
    }

def get_messages_for_supervisor(messages: list) -> list:
    clean_history = []
    
    for msg in messages:
        if isinstance(msg, HumanMessage):
            clean_history.append(msg)
        elif isinstance(msg, AIMessage):
            clean_history.append(msg)

    return clean_history