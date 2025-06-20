import argparse
import json
import os
import tarfile
import tempfile
import urllib.request
from urllib.error import URLError
from hashlib import sha256
import re
import warnings
import random
import time
import asyncio
import aiohttp
from colorama import Fore, Style, init as colorama_init
import base64
from dotenv import load_dotenv

warnings.filterwarnings("ignore", category=DeprecationWarning)
colorama_init(autoreset=True)

GITHUB_API = "https://api.github.com"

SUSPICIOUS_PATTERNS = [
    b"echo $GITHUB_",
    b"curl ",
    b"wget ",
    b"nc ",
    b"GITHUB_TOKEN",
    b"GITHUB_ENV",
    b"GITHUB_OUTPUT",
    b"set-output",
    b"aws_access_key_id",
    b"aws_secret_access_key",
]

NETWORK_REGEX = re.compile(rb"https?://[^\s\"']+")

ASCII_BANNER = rf"""{Fore.CYAN}

 ██████╗ ██████╗ ███╗   ███╗██████╗  █████╗ ████████╗   ███████╗ ██████╗ █████╗ 
██╔════╝██╔═══██╗████╗ ████║██╔══██╗██╔══██╗╚══██╔══╝   ██╔════╝██╔════╝██╔══██╗
██║     ██║   ██║██╔████╔██║██████╔╝███████║   ██║█████╗███████╗██║     ███████║
██║     ██║   ██║██║╚██╔╝██║██╔══██╗██╔══██║   ██║╚════╝╚════██║██║     ██╔══██║
╚██████╗╚██████╔╝██║ ╚═╝ ██║██████╔╝██║  ██║   ██║      ███████║╚██████╗██║  ██║
 ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝      ╚══════╝ ╚═════╝╚═╝  ╚═╝
                                                                                

{Style.RESET_ALL}
"""

CREATIVE_QUOTES = [
    "“To improve is to change; to be perfect is to change often.” – Winston Churchill",
    "“Change is the end result of all true learning.” – Leo Buscaglia",
    "“Progress is impossible without change.” – George Bernard Shaw",
    "“Security is not a product, but a process.” – Bruce Schneier",
    "“The best way to predict the future is to invent it.” – Alan Kay",
    "“Stay alert, stay safe!”",
    "“Every change is an opportunity in disguise.”",
    "“Let's keep things secure, one commit at a time!”",
    "“Another day, another scan!”",
    "“May the code be ever in your favor.”",
    "“The only way to do great work is to love what you do.” – Steve Jobs",
    "“Code is like humor. When you have to explain it, it's bad.” – Cory House",
    "“First, solve the problem. Then, write the code.” – John Johnson",
    "“Simplicity is the soul of efficiency.” – Austin Freeman",
    "“The quieter you become, the more you can hear.” – Ram Dass",
    "“Every scan is a step towards a safer world!”",
    "“Let's catch those sneaky bugs together!”",
    "“Your code is your castle. Guard it well!”",
    "“A secure repo is a happy repo!”",
    "“Keep calm and scan on!”",
    "“The journey of a thousand commits begins with a single scan.”",
]

# 1. Advanced suspicious patterns (YARA-like, regex, obfuscation, eval, etc.)
ADVANCED_PATTERNS = [
    (re.compile(rb"(base64\.b64decode|btoa|atob|decode\()"), "Base64 decode usage"),
    (re.compile(rb"(eval\(|exec\()"), "Dynamic code execution (eval/exec)"),
    (re.compile(rb"(importlib\.import_module|__import__)"), "Dynamic import"),
    (re.compile(rb"(subprocess\.Popen|os\.system|popen\()"), "Shell execution"),
    (re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}"), "Long base64-like string"),
    (re.compile(rb"(curl|wget|http[s]?://)"), "Network call"),
    (re.compile(rb"(echo\s+\$GITHUB_|GITHUB_TOKEN|aws_secret_access_key)"), "Secrets exfiltration"),
]

def get_random_quote():
    return random.choice(CREATIVE_QUOTES)

def progressive_print(msg, delay=0.5):
    print(msg)
    time.sleep(delay)

def send_slack_message(webhook_url: str, text: str) -> None:
    if not webhook_url:
        print(f"{Fore.YELLOW}[!] No Slack webhook URL provided. Skipping notification.{Style.RESET_ALL}")
        return
    data = json.dumps({"text": text}).encode()
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            resp.read()
        print(f"{Fore.GREEN}[Slack] Notification sent successfully!{Style.RESET_ALL}")
    except URLError as e:
        print(f"{Fore.RED}Failed to send Slack notification: {e}{Style.RESET_ALL}")

async def fetch_archive_async(session, owner_repo, token=None):
    url = f"{GITHUB_API}/repos/{owner_repo}/tarball"
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    async with session.get(url, headers=headers) as resp:
        resp.raise_for_status()
        return await resp.read()

def compute_checksums(tar_bytes):
    checksums = {}
    with tempfile.TemporaryDirectory() as td:
        tar_path = os.path.join(td, "repo.tar.gz")
        with open(tar_path, "wb") as f:
            f.write(tar_bytes)
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(td)
        root_dir = next(os.scandir(td)).path
        for root, dirs, files in os.walk(root_dir):
            for name in files:
                path = os.path.join(root, name)
                rel = os.path.relpath(path, root_dir)
                with open(path, "rb") as f:
                    content = f.read()
                checksums[rel] = sha256(content).hexdigest()
    return checksums

def find_suspicious(tar_bytes):
    suspicious = []
    network_endpoints = set()
    with tempfile.TemporaryDirectory() as td:
        tar_path = os.path.join(td, "repo.tar.gz")
        with open(tar_path, "wb") as f:
            f.write(tar_bytes)
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(td)
        root_dir = next(os.scandir(td)).path
        for root, dirs, files in os.walk(root_dir):
            for name in files:
                path = os.path.join(root, name)
                rel = os.path.relpath(path, root_dir)
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    for pattern in SUSPICIOUS_PATTERNS:
                        if pattern in data:
                            suspicious.append((rel, pattern.decode()))
                    for match in NETWORK_REGEX.findall(data):
                        endpoint = match.decode()
                        if "github.com" not in endpoint:
                            network_endpoints.add(endpoint)
                except Exception:
                    pass
    return suspicious, sorted(network_endpoints)

def find_advanced_suspicious(tar_bytes):
    advanced_hits = []
    with tempfile.TemporaryDirectory() as td:
        tar_path = os.path.join(td, "repo.tar.gz")
        with open(tar_path, "wb") as f:
            f.write(tar_bytes)
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(td)
        root_dir = next(os.scandir(td)).path
        for root, dirs, files in os.walk(root_dir):
            for name in files:
                path = os.path.join(root, name)
                rel = os.path.relpath(path, root_dir)
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    for regex, desc in ADVANCED_PATTERNS:
                        if regex.search(data):
                            advanced_hits.append((rel, desc))
                except Exception:
                    pass
    return advanced_hits

def load_baseline(baseline_file):
    if os.path.exists(baseline_file):
        with open(baseline_file) as f:
            return json.load(f)
    return None

def save_baseline(baseline_file, checksums):
    with open(baseline_file, "w") as f:
        json.dump(checksums, f, indent=2)

def get_baseline_snippet(baseline_file, max_chars=500):
    if not os.path.exists(baseline_file):
        return "No baseline file found."
    with open(baseline_file, "r") as f:
        content = f.read()
    if len(content) > max_chars:
        return content[:max_chars] + "\n... (truncated) ..."
    return content

# 2. Get latest commit/tag/release info (using GitHub API)
async def get_latest_commit_info(session, owner_repo, token=None):
    url = f"{GITHUB_API}/repos/{owner_repo}/commits"
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    async with session.get(url, headers=headers) as resp:
        if resp.status == 200:
            data = await resp.json()
            if data:
                commit = data[0]
                return f"{commit['sha'][:7]} by {commit['commit']['author']['name']} at {commit['commit']['author']['date']}"
    return "Unknown"

# 3. Baseline diff (show what files changed)
def get_baseline_diff(old, new):
    old_files = set(old.keys())
    new_files = set(new.keys())
    added = new_files - old_files
    removed = old_files - new_files
    changed = {f for f in old_files & new_files if old[f] != new[f]}
    lines = []
    if added:
        lines.append("Added: " + ", ".join(added))
    if removed:
        lines.append("Removed: " + ", ".join(removed))
    if changed:
        lines.append("Changed: " + ", ".join(changed))
    return "\n".join(lines) if lines else "No file-level changes."

# 4. Community signals (basic: recent issues with suspicious keywords)
async def get_recent_issues_signals(session, owner_repo, token=None):
    url = f"{GITHUB_API}/repos/{owner_repo}/issues"
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    async with session.get(url, headers=headers, params={"state": "open", "per_page": 5}) as resp:
        if resp.status == 200:
            issues = await resp.json()
            keywords = ["malware", "compromise", "attack", "hack", "security"]
            flagged = []
            for issue in issues:
                if any(kw in issue["title"].lower() or kw in (issue.get("body") or "").lower() for kw in keywords):
                    flagged.append(f"#{issue['number']}: {issue['title']}")
            return flagged
    return []

# 5. (Optional) Stub for uploading baseline to a file-sharing service
def upload_baseline_and_get_link(baseline_file):
    # Stub: In production, upload to S3, Gist, etc.
    return None

async def monitor_repo(owner_repo, token, baseline_file, slack_webhook):
    progressive_print(f"{Fore.MAGENTA}🔗 [{owner_repo}] Fetching repository archive...{Style.RESET_ALL}", 0.2)
    async with aiohttp.ClientSession() as session:
        try:
            archive = await fetch_archive_async(session, owner_repo, token)
            commit_info = await get_latest_commit_info(session, owner_repo, token)
            community_signals = await get_recent_issues_signals(session, owner_repo, token)
        except Exception as e:
            print(f"{Fore.RED}[{owner_repo}] Failed to fetch archive: {e}{Style.RESET_ALL}")
            return

    progressive_print(f"{Fore.MAGENTA}🔍 [{owner_repo}] Computing checksums...{Style.RESET_ALL}", 0.2)
    checksums = compute_checksums(archive)
    progressive_print(f"{Fore.MAGENTA}📖 [{owner_repo}] Loading baseline...{Style.RESET_ALL}", 0.2)
    baseline = load_baseline(baseline_file)

    quote = get_random_quote()

    if baseline is None:
        progressive_print(f"{Fore.YELLOW}📝 [{owner_repo}] Creating baseline for the first time...{Style.RESET_ALL}", 0.2)
        save_baseline(baseline_file, checksums)
        baseline_snippet = get_baseline_snippet(baseline_file)
        send_slack_message(
            slack_webhook,
            f":new: Baseline created for *{owner_repo}*.\n"
            f"*Latest commit:* {commit_info}\n"
            "Monitoring will start from the next run.\n\n"
            f"*Baseline snippet:*\n```json\n{baseline_snippet}\n```\n"
            f"> _{quote}_"
        )
        return

    if checksums != baseline:
        progressive_print(f"{Fore.YELLOW}⚡ [{owner_repo}] Changes detected! Analyzing for suspicious patterns...{Style.RESET_ALL}", 0.2)
        suspicious, endpoints = find_suspicious(archive)
        advanced_hits = find_advanced_suspicious(archive)
        if suspicious:
            progressive_print(f"{Fore.RED}🚨 [{owner_repo}] Suspicious patterns found!{Style.RESET_ALL}", 0.2)
        if advanced_hits:
            progressive_print(f"{Fore.RED}🧬 [{owner_repo}] Advanced suspicious patterns found!{Style.RESET_ALL}", 0.2)
        if endpoints:
            progressive_print(f"{Fore.YELLOW}🌐 [{owner_repo}] External network endpoints found!{Style.RESET_ALL}", 0.2)
        if not suspicious and not endpoints and not advanced_hits:
            progressive_print(f"{Fore.GREEN}✅ [{owner_repo}] No suspicious patterns detected.{Style.RESET_ALL}", 0.2)

        baseline_snippet = get_baseline_snippet(baseline_file)
        baseline_diff = get_baseline_diff(baseline, checksums)
        baseline_link = upload_baseline_and_get_link(baseline_file) or "(link not available)"
        msg_lines = [
            f":rotating_light: *ALERT: Changes detected in `{owner_repo}`!*",
            f"*Latest commit:* {commit_info}",
            "",
            f"> _{quote}_",
            "",
        ]
        if suspicious:
            msg_lines.append("*Suspicious patterns found:*")
            msg_lines.append("```")
            for file, pattern in suspicious:
                msg_lines.append(f"{file} => {pattern}")
            msg_lines.append("```")
        if advanced_hits:
            msg_lines.append("*Advanced suspicious patterns found:*")
            msg_lines.append("```")
            for file, desc in advanced_hits:
                msg_lines.append(f"{file} => {desc}")
            msg_lines.append("```")
        if endpoints:
            msg_lines.append("*External network endpoints detected:*")
            msg_lines.append("```")
            for e in endpoints:
                msg_lines.append(e)
            msg_lines.append("```")
        msg_lines.append(f"*Baseline diff:*\n```{baseline_diff}```")
        msg_lines.append(f"*Current baseline snippet:*\n```json\n{baseline_snippet}\n```")
        if baseline_link:
            msg_lines.append(f"[Full baseline file]({baseline_link})")
        if community_signals:
            msg_lines.append("*Community signals (recent issues):*")
            for issue in community_signals:
                msg_lines.append(f"- {issue}")
        send_slack_message(slack_webhook, "\n".join(msg_lines))
    else:
        progressive_print(f"{Fore.GREEN}✅ [{owner_repo}] No changes since last baseline.{Style.RESET_ALL}", 0.2)
        send_slack_message(
            slack_webhook,
            f":white_check_mark: No changes detected in *{owner_repo}*. All clear!\n"
            f"*Latest commit:* {commit_info}\n"
            f"> _{quote}_"
        )

    progressive_print(f"{Fore.CYAN}💾 [{owner_repo}] Saving new baseline...{Style.RESET_ALL}", 0.2)
    save_baseline(baseline_file, checksums)
    progressive_print(f"{Fore.GREEN}🎉 [{owner_repo}] Done!{Style.RESET_ALL}", 0.2)

def parse_repos_arg(repos_arg):
    if os.path.isfile(repos_arg):
        with open(repos_arg) as f:
            return [line.strip() for line in f if line.strip()]
    return [repo.strip() for repo in repos_arg.split(",") if repo.strip()]

def main():
    print(ASCII_BANNER)
    parser = argparse.ArgumentParser(description="Monitor one or more GitHub Action repos")
    parser.add_argument("repos", help="Comma-separated list of owner/repo or a file with one per line")
    parser.add_argument("--token", help="GitHub token", default=os.getenv("GITHUB_TOKEN"))
    parser.add_argument("--baseline-dir", default="baselines", help="Directory for baseline files")
    parser.add_argument(
        "--slack-webhook",
        default=os.getenv("SLACK_WEBHOOK_URL"),
        help="Slack incoming webhook URL",
    )
    args = parser.parse_args()

    os.makedirs(args.baseline_dir, exist_ok=True)
    repos = parse_repos_arg(args.repos)

    print(f"{Fore.BLUE}✨ Monitoring {len(repos)} repositories in parallel! ✨{Style.RESET_ALL}")

    async def run_all():
        tasks = []
        for repo in repos:
            baseline_file = os.path.join(args.baseline_dir, f"{repo.replace('/', '_')}_baseline.json")
            tasks.append(monitor_repo(repo, args.token, baseline_file, args.slack_webhook))
        await asyncio.gather(*tasks)

    asyncio.run(run_all())

if __name__ == "__main__":
    # Load environment variables from .env if present
    load_dotenv()
    main()
