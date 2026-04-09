import os
import re
import requests
import concurrent.futures
from git import Repo
from threading import Lock

TOKEN = os.getenv("GITHUB_TOKEN")
TARGET_TYPE = os.getenv("TARGET_TYPE")
TARGET_NAME = os.getenv("TARGET_NAME")
REPO_NAME = os.getenv("REPO_NAME")
SCAN_HISTORY = os.getenv("SCAN_HISTORY") == "true"
SCAN_BRANCHES = os.getenv("SCAN_BRANCHES") == "true"
INCLUDE_MEMBERS = os.getenv("INCLUDE_MEMBERS") == "true"

HEADERS = {"Authorization": f"token {TOKEN}"}

WORKDIR = "repos"

print_lock = Lock()
global_findings = 0


####################################
# SECRET PATTERNS
####################################

SECRET_PATTERNS = {

    "AWS_KEY": r"AKIA[0-9A-Z]{16}",
    "GITHUB_TOKEN": r"gh[pousr]_[A-Za-z0-9]{36}",
    "SSH_PRIVATE_KEY": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "RSA_PRIVATE_KEY": r"-----BEGIN RSA PRIVATE KEY-----",
    "EC_PRIVATE_KEY": r"-----BEGIN EC PRIVATE KEY-----",
    "PGP_PRIVATE_KEY": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "GOOGLE_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "STRIPE_SECRET": r"sk_live_[0-9a-zA-Z]{24}",
    "JWT_TOKEN": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "PASSWORD": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"].+?['\"]",
    "SECRET": r"(?i)secret\s*[:=]\s*['\"].+?['\"]",
    "TOKEN": r"(?i)token\s*[:=]\s*['\"].+?['\"]",
    "DATABASE_URL": r"(postgres|mysql|mongodb|redis):\/\/[^ ]+",
    "SLACK_WEBHOOK": r"https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+",
    "DISCORD_WEBHOOK": r"https:\/\/discord\.com\/api\/webhooks\/[A-Za-z0-9\/]+",
    "BASIC_AUTH_URL": r"https?:\/\/[^:\s]+:[^@\s]+@[^@\s]+",

}


####################################
# PRINT HELPERS
####################################

def safe_print(msg):

    with print_lock:
        print(msg)


def print_finding(repo, branch, file, match_type, match):

    global global_findings
    global_findings += 1

    safe_print(f"""
🚨 SECRET FOUND
Repo: {repo}
Branch: {branch}
File: {file}
Type: {match_type}
Match: {match[:120]}
------------------------------------------------------------
""")


####################################
# API HELPERS
####################################

def github_api(url):

    r = requests.get(url, headers=HEADERS)

    if r.status_code != 200:
        return []

    return r.json()


def paginate(url):

    results = []
    page = 1

    while True:

        data = github_api(f"{url}?page={page}")

        if not data:
            break

        results.extend(data)
        page += 1

    return results


def get_org_repos(org):

    data = paginate(f"https://api.github.com/orgs/{org}/repos")

    return [repo["clone_url"] for repo in data]


def get_user_repos(user):

    data = paginate(f"https://api.github.com/users/{user}/repos")

    return [repo["clone_url"] for repo in data]


def get_org_members(org):

    data = paginate(f"https://api.github.com/orgs/{org}/members")

    return [member["login"] for member in data]


####################################
# SCANNING ENGINE
####################################

def scan_text(text, repo, file, branch):

    matches_found = 0

    for name, pattern in SECRET_PATTERNS.items():

        matches = re.findall(pattern, text)

        for match in matches:

            matches_found += 1

            print_finding(
                repo,
                branch,
                file,
                name,
                match
            )

    return matches_found


def scan_branch(repo, repo_name, branch):

    findings = 0

    repo.git.checkout(branch)

    for root, _, files in os.walk(repo.working_tree_dir):

        for file in files:

            path = os.path.join(root, file)

            try:

                with open(path, "r", errors="ignore") as f:

                    findings += scan_text(
                        f.read(),
                        repo_name,
                        path,
                        branch.name
                    )

            except:
                pass

    if SCAN_HISTORY:

        for commit in repo.iter_commits(branch.name):

            for file in commit.stats.files:

                try:

                    blob = commit.tree / file

                    content = blob.data_stream.read().decode(
                        "utf-8",
                        errors="ignore"
                    )

                    findings += scan_text(
                        content,
                        repo_name,
                        file,
                        branch.name
                    )

                except:
                    pass

    return findings


def scan_repo(repo_url):

    repo_name = repo_url.split("/")[-1].replace(".git", "")

    repo_path = f"{WORKDIR}/{repo_name}"

    safe_print(f"\n🔍 START repo: {repo_name}")

    try:

        repo = Repo.clone_from(
            repo_url,
            repo_path,
            depth=None if SCAN_HISTORY else 1
        )

    except Exception as e:

        safe_print(f"❌ clone failed: {repo_name}")
        return 0

    branches = repo.branches if SCAN_BRANCHES else [repo.active_branch]

    repo_findings = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:

        futures = []

        for branch in branches:

            futures.append(
                executor.submit(
                    scan_branch,
                    repo,
                    repo_name,
                    branch
                )
            )

        for future in concurrent.futures.as_completed(futures):

            repo_findings += future.result()

    safe_print(f"""
✅ FINISHED repo: {repo_name}
Secrets found: {repo_findings}
========================================
""")

    return repo_findings


####################################
# MAIN
####################################

def main():

    os.makedirs(WORKDIR, exist_ok=True)

    repos = []

    if REPO_NAME:

        repos = [
            f"https://github.com/{TARGET_NAME}/{REPO_NAME}.git"
        ]

    else:

        if TARGET_TYPE == "org":

            repos.extend(get_org_repos(TARGET_NAME))

            if INCLUDE_MEMBERS:

                members = get_org_members(TARGET_NAME)

                for member in members:

                    repos.extend(get_user_repos(member))

        elif TARGET_TYPE == "user":

            repos.extend(get_user_repos(TARGET_NAME))

    safe_print(f"\n🚀 Parallel scan starting ({len(repos)} repos)\n")

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(8, len(repos))
    ) as executor:

        results = executor.map(scan_repo, repos)

    safe_print(f"""
🎯 ORG SCAN COMPLETE
Total secrets detected: {global_findings}
""")



if __name__ == "__main__":
    main()
