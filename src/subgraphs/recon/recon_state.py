from typing import TypedDict, List, Annotated, Dict, Any
from langchain_core.messages import BaseMessage
import operator, os, ipaddress

class ReconState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    results: Annotated[List[dict], operator.add]
    port_map: dict[str, list[int]]
    scanned_hosts: list[str]
    pending_hosts: list[str]
    done: bool
    step_count: int

def merge_port_map(port_map: Dict[str, List[int]], summary: Dict[str, Any]) -> Dict[str, List[int]]:
    """
    Merge the newest scan summary into the existing port_map.
    Summary is shaped like:
      {
        "summary": {"hosts_found":..., ...},
        "hosts": [{"ip":"10.0.0.1","open_ports":[22,80]}, ...]
      }
    """
    new_map = dict(port_map or {})
    hosts = summary.get("hosts") or []
    for h in hosts:
        ip = h.get("ip")
        ports = h.get("open_ports") or []
        if not ip:
            continue
        # Merge unique, sorted
        merged = sorted(set((new_map.get(ip) or []) + ports))
        new_map[ip] = merged
    return new_map


def derive_pending_hosts(
    port_map: Dict[str, List[int]],
    scanned_hosts: List[str]
) -> List[str]:
    pending = []
    for ip, ports in (port_map or {}).items():
        if ports and ip not in (scanned_hosts or []):
            pending.append(ip)
    return sorted(pending)


def was_version_scan(plan: Dict[str, Any]) -> bool:
    opts = (plan.get("arguments") or {}).get("options") or []
    norm = [(opt or "").strip().lower() for opt in opts]
    return any(
        o == "-sv"
        or o.startswith("-sv")
        or o == "-a"
        or o == "--version-all"
    for o in norm
    )

def target_is_network(target: str) -> bool:
    return "/" in (target or "")