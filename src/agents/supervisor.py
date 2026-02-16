from langchain_core.messages import AIMessage
from src.state import AgentState
from src.model import get_model
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from src.utils import load_prompt
from src.utils import parse_as_json, get_clean_content, last_ai_planner_message, last_recon_summary, last_user_message
from src.logger import logger

def supervisor_node(state: AgentState) -> AgentState:
    llm = get_model()
    SUPERVISOR_INSTRUCTIONS = load_prompt("supervisor.txt")

    clean_messages = get_clean_content(state["messages"])
    
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", SUPERVISOR_INSTRUCTIONS),
        MessagesPlaceholder(variable_name="messages"),
    ])
    logger.info(f"[SUPERVISOR] Invoking Worker Planner. Messages: {clean_messages}")    
    chain = prompt_template | llm.bind(format="json")
    
    response = chain.invoke({"messages": clean_messages})
    data = parse_as_json(response.content)
    logger.info(f"[SUPERVISOR] Worker Planner response: {data}")

    return AgentState(
        messages=[AIMessage(content=data.get("message", "Supervisor finished"))],
        next_step=data.get("next_step", "FINISH")
    )