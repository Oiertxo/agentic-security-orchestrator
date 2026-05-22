from typing import Any, Dict, List

from langchain_community.callbacks import get_openai_callback
from langchain_core.messages import AIMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.model import get_model
from src.state import AgentState, ReconState
from src.utils.utils import load_prompt, parse_as_json, update_state_tokens


@observe(name="Recon HTTP analyzer")
async def recon_http_analyzer_node(
    state: AgentState, config: RunnableConfig
) -> AgentState:
    llm = get_model()
    system_prompt = load_prompt("recon_http_analyzer.txt")

    recon_state: ReconState = state["recon"]
    port_map = recon_state.get("port_map", {})

    logger.info("[RECON_HTTP_ANALYZER] Entering HTTP analyzer node")

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            (
                "system",
                """HTTP SAMPLE DATA:

                Target: {target}

                HTML samples:
                {html_samples}
                """,
            ),
        ]
    )

    updated_port_map = port_map.copy()

    for ip, ports in port_map.items():
        for port, meta in ports.items():
            html_samples_dict = meta.get("html_samples", {})
            if not html_samples_dict:
                continue

            # Convert dict to list
            samples = list(html_samples_dict.values())

            if not samples:
                continue

            llm_input: Dict[str, Any] = {
                "target": f"{ip}:{port}",
                "html_samples": format_html_samples(samples),
            }

            summary = [
                {"path": s.get("path"), "status": s.get("status")} for s in samples
            ]

            logger.info(f"[RECON_HTTP_ANALYZER] Calling LLM: {ip}:{port}: {summary}")

            chain = prompt | llm

            with get_openai_callback() as cb:
                raw_result = await chain.ainvoke(llm_input, config=config)

            # Tokens tracking
            state_tokens, new_tokens = update_state_tokens(cb, recon_state)
            recon_state["tokens"]["token_count"] = state_tokens
            recon_state["tokens"]["events"].append(new_tokens)

            try:
                data = parse_as_json(raw_result)

                if not isinstance(data, dict):
                    logger.warning("Parsed output is not dict")
                    continue

                data.setdefault("app_name", None)
                data.setdefault("app_version", None)
                data.setdefault("frameworks", [])
            except Exception:
                logger.warning(
                    f"[RECON_HTTP_ANALYZER] Failed to parse LLM output {raw_result}"
                )
                continue

            logger.info(f"[RECON_HTTP_ANALYZER] Result: {data}")

            merge_http_llm_result(meta, data)

    new_recon: ReconState = {
        **recon_state,
        "port_map": updated_port_map,
    }

    return {
        **state,
        "recon": new_recon,
        "messages": state.get("messages")
        + [
            AIMessage(
                content="[SOURCE: RECON_HTTP_ANALYZER] HTTP semantic analysis completed"
            )
        ],
        "next_step": "planner",
    }


def format_html_samples(samples: List[Dict]) -> str:
    parts = []

    for s in samples:
        parts.append(f"""
            PATH: {s["path"]}
            STATUS: {s["status"]}

            {s["body"][:6000]}
            """)

    return "\n\n---\n\n".join(parts)


def merge_http_llm_result(meta, data: Dict[str, Any]):

    if data.get("app_name") and not meta.get("app_name"):
        meta["app_name"] = data["app_name"].lower()

    if data.get("app_version"):
        existing = meta.get("app_version")

        if not existing or len(data["app_version"]) > len(existing):
            meta["app_version"] = data["app_version"]

    if data.get("frameworks"):
        existing = set(meta.get("frameworks", []))
        existing.update(data["frameworks"])
        meta["frameworks"] = sorted(existing)

    if data.get("title") and not meta.get("title"):
        meta["title"] = data["title"]
