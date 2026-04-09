import os
import re
import requests
from git import Repo
from tqdm import tqdm

TOKEN = os.getenv("GITHUB_TOKEN")
TARGET_TYPE = os.getenv("TARGET_TYPE")
TARGET_NAME = os.getenv("TARGET_NAME")
REPO_NAME = os.getenv("REPO_NAME")
SCAN_HISTORY = os.getenv("SCAN_HISTORY") == "true"
SCAN_BRANCHES = os.getenv("SCAN_BRANCHES") == "true"
INCLUDE_MEMBERS = os.getenv("INCLUDE_MEMBERS") == "true"

HEADERS = {"Authorization": f"token {TOKEN}"}

WORKDIR = "repos"
TOTAL_FINDINGS = 0


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

}


####################################
# LOG OUTPUT FORMATTER
####################################

def print_finding(repo, branch, file, match_type, match):

    global TOTAL_FINDINGS
    TOTAL_FINDINGS += 1

    print("\n🚨 SECRET FOUND")
    print(f"Repo: {repo}")
    print(f"Branch: {branch}")
    print(f"File: {file}")
    print(f"Type: {match_type}")
    print(f"Match: {match[:120]}")
    print("-" * 60)


####################################
# API HELPERS
####################################

def github_api(url):

    r = requests.get(url, headers=HEADERS)

    if r.status_code != 200:
        return []

    return r.json()


def get_org_repos(org):

    repos = []
    page = 1

    while True:

        url = f"https://api.github.com/orgs/{org}/repos?page={page}"

        data = github_api(url)

        if not data:
            break

        repos.extend([repo["clone_url"] for repo in data])

        page += 1

    return repos


def get_user_repos(user):

    repos = []
    page = 1

    while True:

        url = f"https://api.github.com/users/{user}/repos?page={page}"

        data = github_api(url)

        if not data:
            break

        repos.extend([repo["clone_url"] for repo in data])

        page += 1

    return repos


def get_org_members(org):

    members = []
    page = 1

    while True:

        url = f"https://api.github.com/orgs/{org}/members?page={page}"

        data = github_api(url)

        if not data:
            break

        members.extend([member["login"] for member in data])

        page += 1

    return members


####################################
# SCANNING ENGINE
####################################

def scan_text(text, repo, file, branch):

    for name, pattern in SECRET_PATTERNS.items():

        matches = re.findall(pattern, text)

        for match in matches:

            print_finding(
                repo,
                branch,
                file,
                name,
                match
            )


def scan_repo(repo_url):

    repo_name = repo_url.split("/")[-1].replace(".git", "")

    repo_path = f"{WORKDIR}/{repo_name}"

    print(f"\n🔍 Scanning repo: {repo_name}")

    repo = Repo.clone_from(repo_url, repo_path)

    branches = repo.branches if SCAN_BRANCHES else [repo.active_branch]

    for branch in branches:

        print(f"📂 Branch: {branch}")

        repo.git.checkout(branch)

        for root, _, files in os.walk(repo_path):

            for file in files:

                path = os.path.join(root, file)

                try:

                    with open(path, "r", errors="ignore") as f:

                        scan_text(
                            f.read(),
                            repo_name,
                            path,
                            branch.name
                        )

                except:
                    pass

        if SCAN_HISTORY:

            print("🕘 Scanning commit history...")

            for commit in repo.iter_commits(branch.name):

                for file in commit.stats.files:

                    try:

                        blob = commit.tree / file

                        content = blob.data_stream.read().decode(
                            "utf-8",
                            errors="ignore"
                        )

                        scan_text(
                            content,
                            repo_name,
                            file,
                            branch.name
                        )

                    except:
                        pass


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

    print(f"\n🚀 Starting scan across {len(repos)} repositories\n")

    for repo in tqdm(repos):

        try:

            scan_repo(repo)

        except Exception as e:

            print(f"⚠️ Error scanning {repo}: {e}")

    print("\n✅ Scan complete")
    print(f"🔎 Total findings: {TOTAL_FINDINGS}")


if __name__ == "__main__":
    main()
