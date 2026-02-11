from langchain_core.messages import AIMessage
from src.subgraphs.recon.state import ReconState
from src.model import get_model
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from src.utils import load_prompt, parse_as_json, get_clean_content
from src.logger import logger

def recon_planner_node(state: ReconState):
    llm = get_model()
    RECON_AGENT_PROMPT = load_prompt("recon.txt")
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", RECON_AGENT_PROMPT),
        MessagesPlaceholder("messages"),
    ])
    
    response = (prompt | llm.bind(format="json")).invoke({"messages": get_clean_content(state["messages"])})
    
    try:
        data = parse_as_json(response)
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
        is_done = data.get("done", False)
    except:
        is_done = False

    return {
        "messages": [AIMessage(content=response.content)],
        "done": is_done
    }