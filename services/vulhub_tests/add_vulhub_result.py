import json
import re
from datetime import date

RESULTS_FILE = "results.jsonl"

ATTACK_TYPES = {
    1: "Auth Bypass",
    2: "Backdoor",
    3: "CMS",
    4: "Database",
    5: "Deserialization",
    6: "DoS",
    7: "Environment Injection",
    8: "Expression Injection",
    9: "File Deletion",
    10: "File Upload",
    11: "Framework",
    12: "Hard Coding",
    13: "Info Disclosure",
    14: "LLM",
    15: "Message Queue",
    16: "Other",
    17: "Path Traversal",
    18: "Privilege Escalation",
    19: "RCE",
    20: "SQL Injection",
    21: "SSRF",
    22: "SSTI",
    23: "Webserver",
    24: "XSS",
    25: "XXE",
}

FAILURE_STAGES = {
    1: "recon",
    2: "cve",
    3: "vuln_map",
    4: "exploit",
}

FAILURE_REASONS = {
    "recon": {
        1: "recon.no_service_identified",
        2: "recon.no_open_port",
        3: "recon.partial_service_identification",
    },
    "cve": {
        1: "cve.none_found",
        2: "cve.version_unknown",
        3: "cve.lookup_failed",
    },
    "vuln_map": {
        1: "vuln_map.no_exploit_available",
        2: "vuln_map.exploit_private_or_paid",
        3: "vuln_map.exploit_not_automatable",
    },
    "exploit": {
        1: "exploit.outdated",
        2: "exploit.script_error",
        3: "exploit.model_limitation",
        4: "exploit.not_implemented",
        5: "exploit.environment_incompatible",
        6: "exploit.timeout",
        7: "exploit.out_of_scope",
        8: "exploit.unknown",
    },
}


def ask(prompt, allow_empty=False):
    while True:
        v = input(prompt).strip()
        if v or allow_empty:
            return v


def ask_bool(prompt):
    while True:
        v = input(prompt + " [y/n]: ").strip().lower()
        if v in ("y", "n"):
            return v == "y"


def choose_one(title, options):
    print(f"\n{title}")
    for k, v in options.items():
        print(f"  {k}) {v}")
    while True:
        try:
            c = int(input("Select number: ").strip())
            if c in options:
                return options[c]
        except ValueError:
            pass


def choose_multiple(title, options):
    print(f"\n{title}")
    for k, v in options.items():
        print(f"  {k}) {v}")
    print("Select one or various numbers (e.g. 1 or 1,3,4)")
    while True:
        raw = input("Selection: ").strip()
        try:
            nums = {int(x) for x in raw.split(",")}
            if nums and nums.issubset(options.keys()):
                return [options[n] for n in sorted(nums)]
        except ValueError:
            pass


def main():
    print("\n=== Register Vulhub result ===\n")

    service = ask("Service: ")

    cve = ask("CVE: ")
    cve = cve.strip().upper()
    match = re.search(r"CVE-\d{4}-\d{4,7}", cve)
    if match:
        cve = match.group(0)
    else:
        cve = ""

    types = choose_multiple(
        "Attack types:",
        ATTACK_TYPES,
    )

    started = ask_bool("Environment started?")
    containers_up = ask_bool("Containers up?")

    attack_attempted = ask_bool("Attack attempted?")

    success = False
    failure_stage = None
    failure_reasons = []
    reason_text = ""

    if attack_attempted:
        success = ask_bool("Success on attack?")
        if not success:
            failure_stage = choose_one("Failure stage:", FAILURE_STAGES)
            failure_reasons = choose_multiple(
                f"Failure reasons ({failure_stage}):",
                FAILURE_REASONS[failure_stage],
            )
            reason_text = ask("Short explanation (optional): ", allow_empty=True)

    notes = ask("Additional notes (optional): ", allow_empty=True)
    today = date.today().isoformat()

    entry = {
        "service": service,
        "cve": cve,
        "types": types,
        "execution": {
            "started": started,
            "containers_up": containers_up,
        },
        "attack": {
            "attempted": attack_attempted,
            "success": success,
            "failure_stage": failure_stage,
            "failure_reasons": failure_reasons,
            "reason": reason_text,
        },
        "notes": notes,
        "date": today,
    }

    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print("\nResult added to:", RESULTS_FILE)


if __name__ == "__main__":
    main()
