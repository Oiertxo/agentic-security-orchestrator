import re
import ssl
import urllib.request
from urllib.error import HTTPError, URLError

ssl._create_default_https_context = ssl._create_unverified_context

URLS = [
    "https://vulhub-org.translate.goog/environments?tag=Auth+Bypass&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp",
    "https://vulhub-org.translate.goog/environments?tag=Backdoor&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp",
    "https://vulhub-org.translate.goog/environments?tag=CMS&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Database&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Deserialization&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Environment+Injection&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Expression+Injection&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=File+Deletion&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=File+Upload&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Framework&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Hard+Coding&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Info+Disclosure&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=LLM&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Message+Queue&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Other&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Path+Traversal&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Privilege+Escalation&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=RCE&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=SQL+Injection&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=SSRF&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=SSTI&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=Webserver&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=XSS&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
    "https://vulhub-org.translate.goog/environments?tag=XXE&_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp&_x_tr_hist=true",
]

OUTPUT_FILE = "results.txt"
TIMEOUT = 20


def fetch_url(url: str) -> str:
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (compatible; VulhubScraper/1.0)"}
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", errors="ignore")


def extract_tag_from_url(url: str) -> str:
    return url.split("tag=")[1].split("&_x_tr_sl")[0].replace("+", " ")


def extract_paths(text: str) -> list[str]:
    results = []
    seen = set()

    for line in text.splitlines():
        if "vulhub/tree/master/" not in line:
            continue

        try:
            part = line.split("vulhub/tree/master/", 1)[1]
            path = re.split(r"[\"\\]", part)[0].strip()
            if path and path not in seen:
                seen.add(path)
                results.append(path)
        except IndexError:
            continue

    return results


def main():
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        for url in URLS:
            tag = extract_tag_from_url(url)
            out.write("#" * 80 + "\n")
            out.write(f"# {tag}\n")
            out.write("#" * 80 + "\n\n")

            try:
                print(f"[+] Downloading: {url}")
                content = fetch_url(url)
            except (HTTPError, URLError) as e:
                out.write(f"ERROR while downloading URL: {e}\n\n")
                continue

            paths = extract_paths(content)

            if not paths:
                out.write("(No results found)\n\n")
                continue

            for p in paths:
                out.write(p + "\n")

            out.write(f"\nTotal: {len(paths)} results\n\n")

    print(f"[✓] Results stored in {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
