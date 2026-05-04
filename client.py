import argparse
import json
import sys

import requests


def stream_audit(query, thread_id, start_new):
    url = "http://localhost:8000/chat"
    payload = {"query": query, "thread_id": thread_id, "start_new": start_new}

    status_msg = "Restarting" if start_new else "Continuing"
    print(f"\n{status_msg} session on thread: {thread_id}")
    print(f"Query: {query}")
    print("-" * 50)

    try:
        with requests.post(url, json=payload, stream=True) as response:
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
        print(f"\n\nConnection error: Is the orchestrator running on {url}?")
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

    args = parser.parse_args()

    try:
        stream_audit(args.query, args.thread, args.fresh)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Closing...")
        sys.exit(0)
