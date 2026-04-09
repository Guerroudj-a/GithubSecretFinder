import os
import re
import requests
import concurrent.futures
from git import Repo
from threading import Lock


####################################
# ENV CONFIG
####################################

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

    "OPENSSH_KEY": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "RSA_PRIVATE_KEY": r"-----BEGIN RSA PRIVATE KEY-----",
    "EC_PRIVATE_KEY": r"-----BEGIN EC PRIVATE KEY-----",
    "PGP_PRIVATE_KEY": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",

    "GOOGLE_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "STRIPE_SECRET": r"sk_live_[0-9a-zA-Z]{24}",

    "JWT_TOKEN": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",

    "PASSWORD":
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"].+?['\"]",

    "SECRET":
        r"(?i)secret\s*[:=]\s*['\"].+?['\"]",

    "TOKEN":
        r"(?i)token\s*[:=]\s*['\"].+?['\"]",

    "DATABASE_URL":
        r"(postgres|mysql|mongodb|redis):\/\/[^ ]+",

    "SLACK_WEBHOOK":
        r"https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+",

    "DISCORD_WEBHOOK":
        r"https:\/\/discord\.com\/api\/webhooks\/[A-Za-z0-9\/]+",

    "BASIC_AUTH_URL":
        r"https?:\/\/[^:\s]+:[^@\s]+@[^@\s]+",

    "ENV_FILE_REFERENCE":
        r"\.env",

}


####################################
# THREAD SAFE PRINT
####################################

def safe_print(message):
    with print_lock:
        print(message)


####################################
# FINDING OUTPUT
####################################

def print_finding(repo_url, repo_name, branch, file_path, match_type, match):

    global global_findings
    global_findings += 1

    repo_root = os.path.join(WORKDIR, repo_name)

    try:
        relative_path = os.path.relpath(file_path, repo_root)
    except:
        relative_path = file_path

    clean_repo_url = repo_url.replace(".git", "")

    file_link = f"{clean_repo_url}/blob/{branch}/{relative_path}"

    safe_print(f"""
🚨 SECRET FOUND
Repo: {clean_repo_url}
Branch: {branch}
File: {relative_path}
Link: {file_link}
Type: {match_type}
Match: {match[:120]}
------------------------------------------------------------
""")


####################################
# GITHUB API HELPERS
####################################

def github_api(url):

    response = requests.get(url, headers=HEADERS)

    if response.status_code != 200:
        return []

    return response.json()


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

    repos = paginate(
        f"https://api.github.com/orgs/{org}/repos"
    )

    return [repo["clone_url"] for repo in repos]


def get_user_repos(user):

    repos = paginate(
        f"https://api.github.com/users/{user}/repos"
    )

    return [repo["clone_url"] for repo in repos]


def get_org_members(org):

    members = paginate(
        f"https://api.github.com/orgs/{org}/members"
    )

    return [member["login"] for member in members]


####################################
# TEXT SCANNER
####################################

def scan_text(text, repo_url, repo_name, file_path, branch):

    findings = 0

    for secret_type, pattern in SECRET_PATTERNS.items():

        matches = re.findall(pattern, text)

        for match in matches:

            findings += 1

            print_finding(
                repo_url,
                repo_name,
                branch,
                file_path,
                secret_type,
                match
            )

    return findings


####################################
# BRANCH SCANNER
####################################

def scan_branch(repo, repo_url, repo_name, branch):

    findings = 0

    repo.git.checkout(branch)

    for root, _, files in os.walk(repo.working_tree_dir):

        for file in files:

            path = os.path.join(root, file)

            try:

                with open(path, "r", errors="ignore") as f:

                    findings += scan_text(
                        f.read(),
                        repo_url,
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
                        repo_url,
                        repo_name,
                        file,
                        branch.name
                    )

                except:
                    pass

    return findings


####################################
# REPO SCANNER
####################################

def scan_repo(repo_url):

    repo_name = repo_url.split("/")[-1].replace(".git", "")

    repo_path = f"{WORKDIR}/{repo_name}"

    safe_print(f"\n🔍 START repo: {repo_url}")

    try:

        repo = Repo.clone_from(
            repo_url,
            repo_path,
            depth=None if SCAN_HISTORY else 1
        )

    except Exception as e:

        safe_print(f"❌ clone failed: {repo_url}")
        return 0

    branches = repo.branches if SCAN_BRANCHES else [repo.active_branch]

    repo_findings = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:

        futures = [

            executor.submit(
                scan_branch,
                repo,
                repo_url,
                repo_name,
                branch
            )

            for branch in branches
        ]

        for future in concurrent.futures.as_completed(futures):

            repo_findings += future.result()

    safe_print(f"""
✅ FINISHED repo: {repo_url}
Secrets found: {repo_findings}
========================================
""")

    return repo_findings


####################################
# MAIN EXECUTION
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

            repos.extend(
                get_org_repos(TARGET_NAME)
            )

            if INCLUDE_MEMBERS:

                members = get_org_members(
                    TARGET_NAME
                )

                for member in members:

                    repos.extend(
                        get_user_repos(member)
                    )

        elif TARGET_TYPE == "user":

            repos.extend(
                get_user_repos(TARGET_NAME)
            )

    safe_print(
        f"\n🚀 Parallel scan starting ({len(repos)} repos)\n"
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(8, len(repos))
    ) as executor:

        executor.map(scan_repo, repos)

    safe_print(f"""
🎯 SCAN COMPLETE
Total secrets detected: {global_findings}
""")


if __name__ == "__main__":
    main()
