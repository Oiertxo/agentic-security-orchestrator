from langchain_core.messages import AIMessage
from src.state import AgentState
from src.model import get_model
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from src.utils import load_prompt
import json

def supervisor_node(state: AgentState):
    llm = get_model()
    SUPERVISOR_INSTRUCTIONS = load_prompt("supervisor.txt")
    
    supervisor_prompt_template = ChatPromptTemplate.from_messages([
        ("system", SUPERVISOR_INSTRUCTIONS),
        MessagesPlaceholder("messages"),
    ])
    
    structured_llm = llm.bind(format="json")
    chain = supervisor_prompt_template | structured_llm
    print("Supervisor debug initial request: ", state["messages"])
    response = chain.invoke({"messages": state["messages"]})
    content = response.content
    print("Supervisor debug: ", content)
    if not isinstance(content, str):
        content = str(content)
    
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        data = {"next_step": "FINISH", "message": "Error: Invalid JSON from Supervisor."}

    return AgentState(
        messages=[AIMessage(content=data.get("message", ""))],
        next_step=data.get("next_step", "FINISH")
    )