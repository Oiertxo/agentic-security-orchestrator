import argparse
import json
import sys

import requests

API_URL = "http://localhost:8000/chat"


def build_intended_cve():
    print("\n[+] CVE injection mode\n")

    target_ip = input("Target IP: ").strip()
    target_port = int(input("Target Port: ").strip())

    # --- CVE BASIC ---
    cve_id = input("CVE ID (e.g. CVE-2021-44790): ").strip()

    print("\n--- CVSS ---")
    cvss_v31 = input("CVSS v3.1 (default null): ").strip()
    cvss_v30 = input("CVSS v3.0 (default null): ").strip()
    cvss_v2 = input("CVSS v2 (default null): ").strip()

    # Convert
    cvss_v31 = float(cvss_v31) if cvss_v31 else None
    cvss_v30 = float(cvss_v30) if cvss_v30 else None
    cvss_v2 = float(cvss_v2) if cvss_v2 else None

    # --- VERSION ---
    print("\n--- MATCHED VERSION ---")
    version_raw = input("Version (e.g. 2.4.50): ").strip()

    try:
        version_tuple = [int(x) for x in version_raw.split(".")]
    except Exception:
        version_tuple = None

    # --- CONFIGURATIONS ---
    print("\n--- CONFIGURATIONS ---")
    use_config = input("Add configuration range? (y/n): ").strip().lower()

    configurations = []
    if use_config == "y":
        config = {
            "versionStartIncluding": input(
                "versionStartIncluding (default null): "
            ).strip()
            or None,
            "versionStartExcluding": input(
                "versionStartExcluding (default null): "
            ).strip()
            or None,
            "versionEndIncluding": input("versionEndIncluding (default null): ").strip()
            or None,
            "versionEndExcluding": input("versionEndExcluding (default null): ").strip()
            or None,
        }
        configurations.append(config)

    # --- FOUND BY ---
    print("\n--- FOUND BY ---")
    found_by = input("Found by (comma separated) [default: manual_override]: ").strip()
    if not found_by:
        found_by_list = ["manual_override"]
    else:
        found_by_list = [x.strip() for x in found_by.split(",")]

    # Max CVSS
    calculated_max_cvss = max(
        [x for x in [cvss_v31, cvss_v30, cvss_v2] if x is not None],
        default=10.0,
    )

    # --- FINAL OBJECT ---
    cve_obj = {
        "cve_id": cve_id,
        "cvss_v31_base": cvss_v31,
        "cvss_v30_base": cvss_v30,
        "cvss_v2_base": cvss_v2,
        "configurations": configurations,
        "found_by": found_by_list,
        "matched_version": {
            "raw": version_raw,
            "type": "single",
            "version": version_tuple,
        },
        "calculated_max_cvss": calculated_max_cvss,
        "severity_label": "CRITICAL" if (cvss_v31 or 10.0) >= 9 else "HIGH",
    }

    return {
        "target_ip": target_ip,
        "target_port": target_port,
        "cve": cve_obj,
    }


def build_payload(query, thread_id, start_new, use_cve):
    payload = {
        "query": query,
        "thread_id": thread_id,
        "start_new": start_new,
    }

    if use_cve:
        payload["intended_cve"] = build_intended_cve()

    return payload


def stream_audit(payload):
    status_msg = "Starting" if payload["start_new"] else "Continuing"
    print(f"\n{status_msg} session on thread: {payload['thread_id']}")
    print(f"Query: {payload['query']}")
    print("-" * 50)

    try:
        with requests.post(API_URL, json=payload, stream=True) as response:
            if response.status_code != 200:
                print(f"Server error ({response.status_code}): {response.text}")
                return

            for line in response.iter_lines():
                if line:
                    decoded_line = line.decode("utf-8")
                    if decoded_line.startswith("data: "):
                        try:
                            content = json.loads(decoded_line[6:])
                        except json.JSONDecodeError:
                            continue

                        if "token" in content:
                            print(content["token"], end="", flush=True)

                        elif "node" in content:
                            node_name = content["node"].upper()
                            print(f"\n\n[SYSTEM] Node: {node_name}")
                            print(" > ", end="", flush=True)

                        elif "error" in content:
                            print(f"\n\n[BACKEND ERROR]: {content['error']}")

                        elif content.get("status") == "done":
                            print("\n\nStream finished.")

    except requests.exceptions.ConnectionError:
        print(f"\n\nConnection error: Is the orchestrator running on {API_URL}?")
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Agentic Security Orchestrator CLI Client"
    )

    parser.add_argument("query", type=str, help="The security task or question")

    parser.add_argument(
        "--thread",
        "-t",
        type=str,
        default="default_thread",
        help="Thread ID for persistence",
    )

    parser.add_argument(
        "--fresh",
        "-f",
        action="store_true",
        help="Start a new audit (wipes old thread data)",
    )

    parser.add_argument(
        "--cve",
        action="store_true",
        help="Enable intended CVE injection",
    )

    args = parser.parse_args()

    try:
        payload = build_payload(
            query=args.query,
            thread_id=args.thread,
            start_new=args.fresh,
            use_cve=args.cve,
        )

        stream_audit(payload)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Closing...")
        sys.exit(0)
