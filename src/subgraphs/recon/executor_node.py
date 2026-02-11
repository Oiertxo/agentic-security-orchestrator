from langchain_core.messages import AIMessage, HumanMessage
from src.subgraphs.recon.state import ReconState
from src.subgraphs.recon.executor_client import call_recon_engine
from src.utils import parse_as_json
from src.logger import logger
import json

def recon_executor_node(state: ReconState):
    step = int(state.get("step_count", 0)) + 1

    raw = state["messages"][-1].content
    try:
        plan = parse_as_json(raw)
    except Exception:
        result = {"ok": False, "error": "planner_output_not_json", "raw": raw}
        return {
            "messages": [AIMessage(content=f"[SOURCE: recon_engine]\n{json.dumps(result)}")],
            "results": [result],
            "step_count": step,
            "done": False,
        }

    engine_result = call_recon_engine(plan=plan)
    logger.info(f"[RECON_EXECUTOR] Recon engine result: {engine_result}")

    return {
        "messages": [HumanMessage(content=f"[SOURCE: recon_engine]\n{json.dumps(engine_result)}")],
        "results": [engine_result],
        "step_count": step,
        "done": False,
    }