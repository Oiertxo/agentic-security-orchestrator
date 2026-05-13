import json
import re
from typing import Any, Dict, Optional
from urllib.parse import urljoin

from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.state import AgentState, ReconState, ServiceMeta
from src.subgraphs.recon.recon_executor_client import call_curl

OPENAPI_VERSION_RE = re.compile(r'"version"\s*:\s*"([^"]+)"')
OPENAPI_TITLE_RE = re.compile(r'"title"\s*:\s*"([^"]+)"')
COMMON_HTTP_PATHS = [
    "/",
    "/login",
    "/logout",
    "/signin",
    "/auth",
    "/admin",
    "/administrator",
    "/manage",
    "/panel",
    "/dashboard",
    "/manager",
    "/manager/html",
    "/host-manager",
    "/console",
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/api",
    "/api/v1",
    "/api/v2",
    "/rest",
    "/openapi.json",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/v2/api-docs",
    "/v3/api-docs",
    "/wp-admin",
    "/wp-login.php",
    "/wp-json",
    "/user/login",
    "/sites",
    "/index.php",
    "/debug",
    "/status",
    "/health",
    "/metrics",
    "/config",
    "/env",
    "/info",
    "/robots.txt",
    "/.env",
    "/.git",
]
SCRIPT_SRC_RE = re.compile(
    r'(?:<|&lt;)script[^>]*\bsrc=["\']([^"\']+)["\']',
    re.I,
)
API_PATH_RE = re.compile(r'["\'](/api[^"\']+)["\']')
FETCH_RE = re.compile(r"\b(fetch|axios)\b", re.I)
AUTH_RE = re.compile(r"authorization|bearer|jwt|token", re.I)
KEYWORDS_RE = re.compile(
    r"admin|internal|private|debug|test|beta",
    re.I,
)
APP_VERSION_RE = re.compile(
    r'(app|application)[_\- ]?(version|ver)\s*[:=]\s*["\']([^"\']+)["\']',
    re.I,
)
COMMENT_VERSION_RE = re.compile(
    r'@version\s+([^\s]+)|version\s+([0-9]+\.[0-9][^"\']*)',
    re.I,
)
PACKAGE_JSON_RE = re.compile(
    r'"name"\s*:\s*"([^"]+)".+?"version"\s*:\s*"([^"]+)"',
    re.S,
)
ENDPOINT_RE = re.compile(
    r'["\'`](\/(?:api|rest|v\d+|internal|admin|debug)[^"\'`<>\s]*)',
    re.I,
)

ABSOLUTE_URL_RE = re.compile(r"https?:\/\/[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+")

FETCH_RE = re.compile(r"\b(fetch|axios|XMLHttpRequest)\b", re.I)

AUTH_RE = re.compile(
    r"authorization|bearer|jwt|token|x-api-key",
    re.I,
)

STORAGE_RE = re.compile(
    r"localStorage|sessionStorage|indexedDB",
    re.I,
)

ROLE_RE = re.compile(
    r"admin|internal|private|staff|root|debug",
    re.I,
)

VERSION_RE = re.compile(
    r'(version|build|release)[\'"\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    re.I,
)


@observe(name="Recon http")
async def recon_http_node(state: AgentState, config: RunnableConfig) -> AgentState:
    recon_state = state.get("recon", {})
    new_step = int(recon_state.get("step_count", 0)) + 1
    port_map = recon_state.get("port_map", {})

    logger.info(f"[RECON_HTTP] Port map: {port_map}")

    # HTTP lookup
    for ip, ports in port_map.items():
        for port, meta in ports.items():
            if not is_http_service(meta):
                continue

            try:
                await general_http_lookup(
                    ip=ip,
                    port=port,
                    meta=meta,
                )

                logger.info(f"[RECON_HTTP] HTTP_LOOKUP meta updated: {meta}")

            except Exception as e:
                logger.warning(f"[RECON_HTTP] Error on {ip}:{port}: {e}")

    # JS lookup
    for ip, ports in port_map.items():
        for port, meta in ports.items():
            if "js_files" not in meta or not meta["js_files"]:
                continue

            try:
                js_findings = await analyze_js_files(meta["js_files"])
                meta["js_findings"] = js_findings
            except Exception as e:
                logger.warning(f"[RECON_HTTP] JS analysis error on {ip}:{port}: {e}")

    logger.info(f"[RECON_HTTP] Updated port map: {port_map}")

    updated_recon: ReconState = {
        **recon_state,
        "step_count": new_step,
        "port_map": port_map,
    }

    return {**state, "recon": updated_recon, "next_step": "planner"}


async def openapi_http_lookup(port_map):
    for ip, ports in port_map.items():
        for port, meta in ports.items():
            if not is_http_service(meta):
                continue

            url = f"http://{ip}:{port}/openapi.json"
            http = await http_get(url)
            if not http:
                continue

            body = http["body"]
            if '"openapi"' not in body:
                continue

            title = extract_openapi_title(body)
            version = extract_openapi_version(body)

            if title:
                meta["product"] = title
            if version:
                meta["version"] = version

    return port_map


async def general_http_lookup(
    ip: str,
    port: int,
    meta: ServiceMeta,
):
    base_url = f"http://{ip}:{port}"
    js_files: set[str] = set(meta.get("js_files") or [])

    root = await http_get(f"{base_url}/")
    if not root:
        return meta

    scripts = normalize_js_urls(base_url, extract_script_srcs(root["body"]))
    if scripts:
        js_files.update(scripts)

    meta["js_files"] = sorted(js_files)

    logger.info(f"[RECON_HTTP] HTTP_LOOKUP {base_url}/ response: {root}")

    meta.setdefault("headers", {}).update(root["headers"])
    meta.setdefault("cookies", {}).update(root["cookies"])

    title = extract_html_title(root["body"])
    if title:
        meta["title"] = title

    common_paths = COMMON_HTTP_PATHS

    if "http_paths" not in meta:
        meta["http_paths"] = {}

    for path in common_paths:
        resp = await http_get(base_url + path)
        if not resp:
            continue

        logger.info(f"[RECON_HTTP] HTTP_LOOKUP {base_url + path} response: {resp}")

        scripts = normalize_js_urls(base_url, extract_script_srcs(resp["body"]))
        if scripts:
            js_files.update(normalize_js_urls(base_url, scripts))

        meta["http_paths"][path] = resp["status_code"]

        if path in ("/openapi.json", "/v2/api-docs", "/v3/api-docs"):
            app_title = extract_openapi_title(resp["body"])
            app_version = extract_openapi_version(resp["body"])

            if app_title:
                meta["app_name"] = app_title
            if app_version:
                meta["app_version"] = app_version

        if path == "/actuator" and resp["content_type"] == "application/json":
            frameworks = set(meta.get("frameworks") or [])
            frameworks.add("spring-boot")
            meta["frameworks"] = sorted(frameworks)

    meta["js_files"] = sorted(js_files)

    return meta


async def http_get(url: str) -> Optional[Dict[str, Any]]:
    result = await call_curl(
        url=url,
        method="GET",
        timeout=10.0,
        include_headers=True,
    )

    raw = result.get("response", {}).get("stdout")

    if not raw:
        return None

    return parse_http_response(raw)


def parse_http_response(raw: str) -> Dict[str, Any]:
    blocks = raw.split("\nHTTP/")
    last = blocks[-1]
    if not last.startswith("HTTP/"):
        last = "HTTP/" + last

    header_part, body = _split_http(last)
    lines = header_part.splitlines()

    # Status
    status_code = 0
    if lines:
        try:
            status_code = int(lines[0].split()[1])
        except Exception:
            pass

    headers = {}
    cookies = {}

    for line in lines[1:]:
        if ":" not in line:
            continue

        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()

        if key == "set-cookie":
            c_name, c_val = val.split("=", 1)
            cookies[c_name] = c_val.split(";", 1)[0]
        else:
            headers[key] = val

    return {
        "status_code": status_code,
        "headers": headers,
        "cookies": cookies,
        "body": body,
        "content_type": headers.get("content-type"),
    }


def is_http_service(meta: ServiceMeta) -> bool:
    name = (meta.get("name") or "").lower()
    product = (meta.get("product") or "").lower()

    if name in {"http", "https"}:
        return True

    http_indicators = [
        "http",
        "apache",
        "nginx",
        "tomcat",
        "jetty",
        "spring",
        "caddy",
        "iis",
    ]

    return any(indicator in product.lower() for indicator in http_indicators)


def extract_openapi_title(body: str) -> Optional[str]:
    try:
        data = json.loads(body)
        return data.get("info", {}).get("title")
    except Exception:
        pass

    m = re.compile(r'"title"\s*:\s*"([^"]+)"', re.I).search(body)
    if m:
        return m.group(1).strip()

    return None


def extract_openapi_version(body: str) -> Optional[str]:
    try:
        data = json.loads(body)
        return data.get("info", {}).get("version")
    except Exception:
        pass

    m = re.compile(r'"version"\s*:\s*"([^"]+)"', re.I).search(body)
    if m:
        return m.group(1).strip()

    return None


def extract_html_title(body: str) -> Optional[str]:
    m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    return m.group(1).strip() if m else None


def extract_script_srcs(html: str) -> set[str]:
    return set(SCRIPT_SRC_RE.findall(html))


def normalize_js_urls(base_url: str, scripts: set[str]) -> set[str]:
    return {urljoin(base_url + "/", s) for s in scripts}


async def analyze_js_files(js_urls: list[str]) -> dict:
    findings = {
        "api_paths": set(),
        "uses_fetch": False,
        "auth_hints": False,
        "keywords": set(),
        "app_names": set(),
        "app_versions": set(),
        "endpoints": set(),
        "absolute_urls": set(),
        "uses_storage": False,
        "roles_flags": set(),
        "versions": set(),
    }

    for url in js_urls:
        resp = await http_get(url)
        if not resp or not resp.get("body"):
            continue

        body = resp["body"]

        findings["api_paths"].update(API_PATH_RE.findall(body))

        if FETCH_RE.search(body):
            findings["uses_fetch"] = True

        if AUTH_RE.search(body):
            findings["auth_hints"] = True

        findings["keywords"].update(KEYWORDS_RE.findall(body))

        for m in APP_VERSION_RE.findall(body):
            findings["app_versions"].add(m[2])

        for m in PACKAGE_JSON_RE.findall(body):
            findings["app_names"].add(m[0])
            findings["app_versions"].add(m[1])

        findings["endpoints"].update(ENDPOINT_RE.findall(body))
        findings["absolute_urls"].update(ABSOLUTE_URL_RE.findall(body))

        if STORAGE_RE.search(body):
            findings["uses_storage"] = True

        findings["roles_flags"].update(r.lower() for r in ROLE_RE.findall(body))

        for m in VERSION_RE.findall(body):
            findings["versions"].add(m[1])

    return {
        "api_paths": sorted(findings["api_paths"]),
        "uses_fetch": findings["uses_fetch"],
        "auth_hints": findings["auth_hints"],
        "keywords": sorted(findings["keywords"]),
        "app_names": sorted(findings["app_names"]),
        "app_versions": sorted(findings["app_versions"]),
        "endpoints": sorted(findings["endpoints"]),
        "absolute_urls": sorted(findings["absolute_urls"]),
        "uses_storage": findings["uses_storage"],
        "roles_flags": sorted(findings["roles_flags"]),
        "versions": sorted(findings["versions"]),
    }


def _split_http(raw: str) -> tuple[str, str]:
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
        return head, body
    if "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
        return head, body
    return raw, ""
