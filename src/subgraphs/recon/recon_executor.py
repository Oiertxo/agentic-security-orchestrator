import json
import re
from typing import Any, Dict
from xml.etree import ElementTree

from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.state import AgentState, PortMap, ReconState, ServiceMeta
from src.subgraphs.recon.recon_executor_client import call_curl, call_recon_engine
from src.utils.utils import (
    derive_pending_hosts,
    merge_port_map,
    parse_as_json,
    target_is_network,
    was_version_scan,
)

OPENAPI_VERSION_RE = re.compile(r'"version"\s*:\s*"([^"]+)"')
OPENAPI_TITLE_RE = re.compile(r'"title"\s*:\s*"([^"]+)"')


@observe(name="Recon executor")
async def recon_executor_node(state: AgentState, config: RunnableConfig) -> AgentState:
    recon_state = state.get("recon", {})
    new_step = int(recon_state.get("step_count", 0)) + 1

    raw = state["messages"][-1].content
    logger.info(f"[RECON_EXECUTOR_NODE] plan: {raw}")
    try:
        plan = parse_as_json(raw)
    except Exception:
        result = {"ok": False, "error": "planner_output_not_json", "raw": raw}
        return {
            **state,
            "recon": {
                "step_count": new_step,
                "port_map": recon_state.get("port_map", {}),
                "scanned_hosts": recon_state.get("scanned_hosts", []),
                "pending_hosts": recon_state.get("pending_hosts", []),
                "finished": False,
            },
            "messages": [
                HumanMessage(content=f"[SOURCE: recon_engine]\n{json.dumps(result)}")
            ],
        }

    engine_result = await call_recon_engine(plan=plan)

    new_port_map = recon_state.get("port_map", {})
    new_scanned = recon_state.get("scanned_hosts", [])

    if not engine_result.get("ok"):
        summary = {
            "ok": False,
            "error": engine_result.get("error", "Unknown executor error"),
            "scanning_time": (engine_result.get("summary", {})).get("scanning_time", 0),
            "request": engine_result.get("request"),
            "response": engine_result.get("response"),
        }
    else:
        response = engine_result.get("response", {})
        xml_str = response.get("stdout")

        if not xml_str:
            summary = {
                "ok": False,
                "error": "Executor returned no stdout",
                "response": response,
            }
        else:
            parsed = parse_nmap_xml(xml_str)
            summary = parsed["summary"]

            new_port_map = merge_port_map(
                recon_state.get("port_map", {}), parsed["port_map"]
            )
            new_scanned = list(recon_state.get("scanned_hosts", []))
            if was_version_scan(plan):
                target = (plan.get("arguments", {})).get("target")
                if (
                    target
                    and not target_is_network(target)
                    and target not in new_scanned
                ):
                    new_scanned.append(target)

    # HTTP lookup
    new_port_map = await openapi_http_lookup(new_port_map)

    new_pending = derive_pending_hosts(new_port_map, new_scanned)
    logger.info(f"[RECON_EXECUTOR] Recon engine result: {summary}")
    updated_recon: ReconState = {
        **recon_state,
        "results": (recon_state.get("results", [])) + [summary],
        "step_count": new_step,
        "finished": False,
        "port_map": new_port_map,
        "scanned_hosts": new_scanned,
        "pending_hosts": new_pending,
    }

    return {**state, "recon": updated_recon, "next_step": "planner"}


def parse_nmap_xml(xml_str: str) -> Dict[str, Any]:
    try:
        root = ElementTree.fromstring(xml_str)
    except ElementTree.ParseError:
        return {"ok": False, "error": "invalid_xml"}

    runstats = root.find("runstats/finished")
    scanning_time = runstats.get("elapsed") if runstats is not None else None
    finished_at = runstats.get("timestr") if runstats is not None else None

    port_map: PortMap = {}
    hosts_found = 0

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue

        ip = addr_el.get("addr")
        if not ip:
            continue

        hosts_found += 1
        ip_ports = port_map.setdefault(ip, {})

        ports_parent = host.find("ports")
        if ports_parent is None:
            continue

        for port in ports_parent.findall("port"):
            portid = port.get("portid")
            if portid is None:
                continue

            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            p = int(portid)

            service_el = port.find("service")
            meta: ServiceMeta = {
                "name": service_el.get("name") if service_el is not None else None,
                "product": service_el.get("product")
                if service_el is not None
                else None,
                "version": service_el.get("version")
                if service_el is not None
                else None,
                "extrainfo": service_el.get("extrainfo")
                if service_el is not None
                else None,
                "ostype": service_el.get("ostype") if service_el is not None else None,
            }

            existing = ip_ports.get(p, {})
            ip_ports[p] = {
                "name": meta.get("name") or existing.get("name"),
                "product": meta.get("product") or existing.get("product"),
                "version": meta.get("version") or existing.get("version"),
                "extrainfo": meta.get("extrainfo") or existing.get("extrainfo"),
                "ostype": meta.get("ostype") or existing.get("ostype"),
            }

    return {
        "ok": True,
        "summary": {
            "hosts_found": hosts_found,
            "scanning_time": scanning_time,
            "finished_at": finished_at,
        },
        "port_map": port_map,
    }


async def openapi_http_lookup(
    port_map: Dict[str, Dict[int, ServiceMeta]],
) -> Dict[str, Dict[int, ServiceMeta]]:
    """
    - Detect HTTP services in port_map
    - Try to get info of OpenAPI with a curl to openapi.json
    - Extract title/version
    """

    for ip, ports in port_map.items():
        for port, meta in ports.items():
            service_name = (meta.get("name") or "").lower()
            product = (meta.get("product") or "").lower()

            # Try to get OpenAPI info
            if service_name == "http" or "http" in product:
                url = f"http://{ip}:{port}/openapi.json"

                logger.info(f"[HTTP_LOOKUP] Probing OpenAPI at {url}")

                try:
                    result = await call_curl(
                        url=url,
                        method="GET",
                        timeout=10.0,
                    )
                except Exception as e:
                    logger.warning(f"[HTTP_LOOKUP] Error probing {url}: {e}")
                    continue

                logger.info(f"[HTTP_LOOKUP] Result: {result}")
                stdout = (result.get("response") or {}).get("stdout", "")
                if not stdout or '"openapi"' not in stdout:
                    continue

                # Extract title / version
                title_match = OPENAPI_TITLE_RE.search(stdout)
                version_match = OPENAPI_VERSION_RE.search(stdout)

                if title_match:
                    meta["product"] = title_match.group(1)

                if version_match:
                    meta["version"] = version_match.group(1)

    return port_map
