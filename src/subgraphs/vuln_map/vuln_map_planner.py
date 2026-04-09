import json
from typing import Any, Dict

from langchain_core.messages import AIMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.model import get_model
from src.schemas import PlannerSchema
from src.state import AgentState, PlannerOutput, VulnMapState
from src.utils.exploit_reader import save_exploit_locally
from src.utils.toon_formatter import (
    pending_services_for_search_to_toon,
    port_map_to_toon,
    vulnerabilities_to_toon,
)
from src.utils.utils import load_prompt


@observe(name="Vuln Map planner")
async def vuln_map_planner_node(
    state: AgentState, config: RunnableConfig
) -> AgentState:
    llm = get_model()
    system_prompt = load_prompt("vuln_map.txt")

    recon_state = state.get("recon", {})
    port_map = recon_state.get("port_map", {})
    cve_state = state.get("cve", {})
    vuln_map_state = state.get("vuln_map", {})
    last_result = (
        vuln_map_state.get("results", [])[-1:] if vuln_map_state.get("results") else []
    )

    logger.info(f"[VULN_MAP_PLANNER] State received: {state}")

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            ("system", "Port map (host: open ports): {port_map}"),
            (
                "system",
                "Pending services for exploit search: {pending_services_for_search}",
            ),
            ("system", "Result of last action: {last_result}"),
            ("system", "Vulnerabilities found: {vulnerabilities}"),
        ]
    )

    if not vuln_map_state.get("pending_services_for_search") and not vuln_map_state.get(
        "analyzed_services_for_search"
    ):
        pending_search = {}

        for ip, ports in port_map.items():
            pending_search[ip] = [
                {
                    "port": p,
                    "product": info.get("product"),
                    "version": info.get("version"),
                }
                for p, info in ports.items()
            ]

        vuln_map_state["pending_services_for_search"] = pending_search
        vuln_map_state["found_exploits"] = {}

    last_result = (
        vuln_map_state.get("results", [])[-1:] if vuln_map_state.get("results") else []
    )

    planner_input = {
        "port_map": port_map_to_toon(port_map),
        "pending_services_for_search": pending_services_for_search_to_toon(
            vuln_map_state.get("pending_services_for_search", {})
        ),
        "last_result": last_result,
        "vulnerabilities": vulnerabilities_to_toon(
            cve_state.get("vulnerabilities", {})
        ),
    }

    logger.info(f"[VULN_MAP_PLANNER] Calling LLM with intel: {planner_input}")

    chain = (
        prompt
        | llm.with_structured_output(PlannerSchema, method="json_mode", strict=True)
    ).with_types(
        input_type=Dict[str, Any],
        output_type=PlannerSchema,
    )

    try:
        raw_result = await chain.ainvoke(planner_input, config=config)
        result = PlannerSchema.model_validate(raw_result)
        data = result.model_dump(mode="json")
    except Exception as e:
        logger.error(f"[VULN_MAP_PLANNER] Parsing error: {e}")
        data = {"finished": True, "next_tool": None, "arguments": {}}

    logger.info(f"[VULN_MAP_PLANNER] Response from LLM: {data}")

    if not data or (not data.get("finished") and not data.get("next_tool")):
        logger.error("[VULN_MAP_PLANNER] Planner failed to reason. Forcing termination")
        data = {
            "finished": True,
            "next_tool": None,
            "arguments": {},
        }

    is_finished = data.get("finished", False)

    found_exploits = vuln_map_state.get("found_exploits", {})
    if is_finished:
        for _, exploits in found_exploits.items():
            for exp in exploits:
                path_in_kali = exp.get("path", "")
                edb_id = exp.get("edb_id", "")

                local_path = save_exploit_locally(path_in_kali, edb_id)
                if local_path:
                    exp["local_path"] = local_path

    new_planner: PlannerOutput = {
        "next_tool": data.get("next_tool", ""),
        "arguments": data.get("arguments", {}),
    }
    new_vuln_map_state: VulnMapState = {
        **vuln_map_state,
        "planner": new_planner,
        "finished": is_finished,
    }

    return {
        **state,
        "vuln_map": new_vuln_map_state,
        "messages": state.get("messages") + [AIMessage(content=json.dumps(data))],
        "next_step": "supervisor" if is_finished else "executor",
    }
