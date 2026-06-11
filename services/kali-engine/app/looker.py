import json
import re
import subprocess
from pathlib import Path

INPUT_FILE = "results.txt"
OUTPUT_FILE = "exploitdb_results.txt"
MAX_EXPLOITS_PER_VULN = 20


def run_searchsploit(query: str) -> dict:
    try:
        result = subprocess.run(
            ["searchsploit", "-j", query], capture_output=True, text=True, check=False
        )
        if result.stdout.strip() == "":
            return {}

        return json.loads(result.stdout)
    except Exception:
        return {}


def extract_queries(entry: str) -> list[str]:
    queries = []

    # CVE
    cve_match = re.search(r"CVE-\d{4}-\d+", entry)
    if cve_match:
        queries.append(cve_match.group(0))

    return list(dict.fromkeys(queries))


def analyze_entry(entry: str) -> dict:
    exploits = []
    seen_edb_ids = set()

    for query in extract_queries(entry):
        if len(exploits) >= MAX_EXPLOITS_PER_VULN:
            break

        data = run_searchsploit(query)
        if not data:
            continue

        results = data.get("RESULTS_EXPLOIT", [])

        for exp in results:
            if len(exploits) >= MAX_EXPLOITS_PER_VULN:
                break

            edb_id = exp.get("EDB-ID")
            if not edb_id or edb_id in seen_edb_ids or ".py" not in exp.get("Path"):
                continue

            if exp.get("Verified", False):
                seen_edb_ids.add(edb_id)
                exploits.append(
                    {
                        "title": exp.get("Title"),
                        "edb_id": edb_id,
                        "verified": True,
                        "path": exp.get("Path"),
                    }
                )

    return {
        "entry": entry,
        "found": bool(exploits),
        "verified": any(e["verified"] for e in exploits),
        "count": len(exploits),
        "exploits": exploits,
    }


def main():
    lines = Path(INPUT_FILE).read_text(errors="ignore").splitlines()

    current_section = None
    total_exploits = 0

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        for line in lines:
            line = line.strip()

            if not line:
                continue

            # Separator ########
            if line.startswith("#" * 10):
                continue

            # Section title: "# Auth Bypass"
            if line.startswith("# "):
                current_section = line[2:].strip()

                out.write("#" * 80 + "\n")
                out.write(f"# {current_section}\n")
                out.write("#" * 80 + "\n\n")
                continue

            # Vulhub entries
            entry = line
            result = analyze_entry(entry)

            if not result["found"]:
                continue

            out.write("=" * 80 + "\n")
            out.write(f"{entry}\n")
            out.write("=" * 80 + "\n")
            out.write(f"ExploitDB: ✅ {result['count']} exploit(s) found\n")
            out.write(
                f"Verified exploits: {'✅ YES' if result['verified'] else '❌ NO'}\n\n"
            )

            for exp in result["exploits"]:
                out.write(
                    f"- [EDB-{exp['edb_id']}] "
                    f"{'[VERIFIED]' if exp['verified'] else ''}\n"
                    f"  {exp['title']}\n"
                    f"  {exp['path']}\n"
                )
                total_exploits += 1

            out.write("\n")

        out.write("\n\n\n" + "=" * 80 + f"\n\nTotal exploit count: {total_exploits}")

    print(f"[+] Results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
