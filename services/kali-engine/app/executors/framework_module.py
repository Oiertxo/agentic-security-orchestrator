import logging
import re
import shlex
import subprocess
from typing import Any, Dict

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

    # Build Metasploit command script
    msf_commands = []
    msf_commands.append(f"use {module_path}")

    for key, value in options.items():
        msf_commands.append(f"set {key} {value}")

    msf_commands.append("run")
    msf_commands.append("exit")

    msf_script = "; ".join(msf_commands)
    cmd = f"msfconsole -q -x {shlex.quote(msf_script)}"

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

        if rc != 0:
            return {
                "status": "FAILURE",
                "details": stderr or stdout or "Metasploit execution failed",
                "artifact": {
                    "stdout": stdout,
                    "stderr": stderr,
                    "returncode": rc,
                },
            }

        if "failed to load module" in stdout:
            return {
                "status": "TECHNICAL_FAILURE",
                "details": "Metasploit module could not be loaded (missing or deprecated)",
                "artifact": {
                    "stdout": stdout,
                    "stderr": stderr,
                    "returncode": rc,
                },
            }

        return {
            "status": "SUCCESS",
            "details": "Metasploit module executed",
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
