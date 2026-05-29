import glob
import re
from datetime import datetime
from statistics import mean, stdev

LOG_PATTERN = "../../data/logs/*.log"

TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

SUP_RE = re.compile(r"\[SUPERVISOR\] Received state:")

TOKENS_RE = re.compile(r"'total_tokens':\s*(\d+)")

STEP_RE = {
    "recon": re.compile(r"'recon':\s*{[^}]*'step_count':\s*(\d+)"),
    "cve": re.compile(r"'cve':\s*{[^}]*'step_count':\s*(\d+)"),
    "vuln_map": re.compile(r"'vuln_map':\s*{[^}]*'step_count':\s*(\d+)"),
    "exploit": re.compile(r"'exploit':\s*{[^}]*'step_count':\s*(\d+)"),
}

START_PHASE_RE = re.compile(r"next_step='(recon|cve|vuln_map|exploit)'")
END_PHASE_RE = {
    "recon": re.compile(r"\[RECON_WORKER_NODE\]"),
    "cve": re.compile(r"\[CVE_WORKER_NODE\]"),
    "vuln_map": re.compile(r"\[VULN_MAP_WORKER_NODE\]"),
    "exploit": re.compile(r"\[EXPLOIT_WORKER_NODE\]"),
}


def parse_time(line):
    m = TS_RE.match(line)
    if m:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    return None


def extract_phase_times(lines):
    phase_times = {
        "recon": 0.0,
        "cve": 0.0,
        "vuln_map": 0.0,
        "exploit": 0.0,
    }

    current_phase = None
    start_time = None

    for line in lines:
        t = parse_time(line)
        if not t:
            continue

        m = START_PHASE_RE.search(line)
        if m:
            current_phase = m.group(1)
            start_time = t
            continue

        if current_phase and start_time:
            if END_PHASE_RE[current_phase].search(line):
                duration = (t - start_time).total_seconds()
                phase_times[current_phase] += duration

                current_phase = None
                start_time = None

    return phase_times


def extract_step_count(text, phase):
    start = text.find(f"'{phase}':")
    if start == -1:
        return 0

    brace_count = 0
    i = start

    while i < len(text):
        if text[i] == "{":
            brace_count += 1
        elif text[i] == "}":
            brace_count -= 1

            if brace_count == 0:
                block = text[start:i]
                break

        i += 1
    else:
        return 0

    m = re.search(r"'step_count':\s*(\d+)", block)
    return int(m.group(1)) if m else 0


def percentile(data, p):
    data = sorted(data)
    k = (len(data) - 1) * (p / 100)
    f = int(k)
    c = min(f + 1, len(data) - 1)
    return data[f] + (data[c] - data[f]) * (k - f)


def extract_metrics(filepath):
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    sup_lines = []

    for line in lines:
        if SUP_RE.search(line):
            sup_lines.append(line)

    if not sup_lines:
        return None

    times = []
    for line in sup_lines:
        parsed_time = parse_time(line)
        if parsed_time is not None:
            times.append(parsed_time)

    duration = (max(times) - min(times)).total_seconds()

    last = sup_lines[-1]

    tokens = sum(int(x) for x in TOKENS_RE.findall(last))

    steps = {}
    for phase in ["recon", "cve", "vuln_map", "exploit"]:
        steps[phase] = extract_step_count(last, phase)

    phase_times = extract_phase_times(lines)

    return {
        "duration": duration,
        "tokens": tokens,
        "steps": steps,
        "phase_times": phase_times,
    }


def main():
    files = glob.glob(LOG_PATTERN)

    print(f"Found {len(files)} logs")

    durations = []
    tokens_list = []
    step_data = {"recon": [], "cve": [], "vuln_map": [], "exploit": []}
    phase_time_data = {
        "recon": [],
        "cve": [],
        "vuln_map": [],
        "exploit": [],
    }

    for file in files:
        res = extract_metrics(file)

        if not res:
            print(f"[WARN] Parsing error: {file}")
            continue

        durations.append(res["duration"])
        tokens_list.append(res["tokens"])

        for k in step_data:
            step_data[k].append(res["steps"][k])

        for phase in phase_time_data:
            phase_time_data[phase].append(res["phase_times"][phase])

    if not durations:
        print("Could not process logs.")
        return

    std_duration = stdev(durations) if len(durations) > 1 else 0
    std_tokens = stdev(tokens_list) if len(tokens_list) > 1 else 0

    print("\n===== RESULTS =====")

    print(f"Execution duration (s): {mean(durations):.2f} ± {std_duration:.2f}")
    print("\n--- Duration percentiles ---")
    print(f"p50: {percentile(durations, 50):.2f}")
    print(f"p90: {percentile(durations, 90):.2f}")
    print(f"p95: {percentile(durations, 95):.2f}")

    print("\n\n--- Duration per phase (mean ± std) ---")

    for phase in phase_time_data:
        data = phase_time_data[phase]

        avg = mean(data)
        std = stdev(data) if len(data) > 1 else 0

        print(f"{phase}: {avg:.2f} ± {std:.2f} s")

    print(f"\nTokens: {mean(tokens_list):.2f} ± {std_tokens:.2f}")
    print("\n--- Token percentiles ---")
    print(f"p50: {percentile(tokens_list, 50):.2f}")
    print(f"p90: {percentile(tokens_list, 90):.2f}")
    print(f"p95: {percentile(tokens_list, 95):.2f}")

    print("\nSteps (mean ± std):")
    for k in step_data:
        avg = mean(step_data[k])
        std = stdev(step_data[k]) if len(step_data[k]) > 1 else 0
        print(f"{k}: {avg:.2f} ± {std:.2f}")


if __name__ == "__main__":
    main()
