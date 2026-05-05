import json
from typing import Any, Dict

from langchain_community.callbacks import get_openai_callback
from langchain_core.messages import AIMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.model import get_model
from src.schemas import PlannerSchema
from src.state import AgentState, PlannerOutput, ReconState
from src.utils.toon_formatter import port_map_to_toon
from src.utils.utils import load_prompt


@observe(name="Recon planner")
async def recon_planner_node(state: AgentState, config: RunnableConfig) -> AgentState:
    llm = get_model()
    system_prompt = load_prompt("recon.txt")
    recon_state = state.get("recon", {})

    logger.info(f"[RECON_PLANNER] State received: {state}")

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            (
                "system",
                """CURRENT STATE:

                User target:
                {user_target}

                Port map:
                {port_map}

                Already scanned hosts:
                {scanned_hosts}

                Pending hosts:
                {pending_hosts}
                """,
            ),
        ]
    )

    planner_input: Dict[str, Any] = {
        "user_target": state.get("user_target"),
        "port_map": port_map_to_toon(
            recon_state.get("port_map", {}), recon_state.get("step_count", 0)
        ),
        "scanned_hosts": recon_state.get("scanned_hosts", []),
        "pending_hosts": recon_state.get("pending_hosts", []),
    }

    logger.info(f"[RECON_PLANNER] Calling LLM: {planner_input}")

    chain = (
        prompt
        | llm.with_structured_output(PlannerSchema, method="json_mode", strict=True)
    ).with_types(
        input_type=Dict[str, Any],
        output_type=PlannerSchema,
    )

    with get_openai_callback() as cb:
        raw_result = await chain.ainvoke(planner_input, config=config)

    tokens = cb.total_tokens

    logger.info(f"[RECON_PLANNER] Callback: {cb}")

    result = PlannerSchema.model_validate(raw_result)
    data = result.model_dump(mode="json")

    logger.info(f"[RECON_PLANNER] Response from LLM: {data}")

    if not data or (not data.get("finished") and not data.get("next_tool")):
        logger.error("[RECON_PLANNER] Planner failed to reason. Forcing termination")
        data = {
            "finished": True,
            "next_tool": None,
            "arguments": {},
            "reason": "Forced finish: LLM returned empty or invalid plan after null results.",
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
        "next_step": "supervisor" if is_finished else "executor",
    }
