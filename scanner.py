import os
import re
import math
import requests
import concurrent.futures
from git import Repo
from threading import Lock


####################################
# CONFIG
####################################

TOKEN = os.getenv("GITHUB_TOKEN")

TARGET_TYPE = os.getenv("TARGET_TYPE")
TARGET_NAME = os.getenv("TARGET_NAME")
REPO_NAME = os.getenv("REPO_NAME")

SCAN_HISTORY = os.getenv("SCAN_HISTORY") == "true"
SCAN_BRANCHES = os.getenv("SCAN_BRANCHES") == "true"
INCLUDE_MEMBERS = True

HEADERS = {"Authorization": f"token {TOKEN}"}

WORKDIR = "repos"

print_lock = Lock()

printed_secrets = set()
scanned_repos = set()
discovered_users = set()

global_findings = 0


####################################
# ENTROPY FILTER
####################################

CONTEXT_KEYWORDS = {

    "token",
    "secret",
    "password",
    "apikey",
    "authorization",
    "bearer",
    "access_key",
    "private_key",
    "client_secret",
    "jwt",
}


IGNORED_CONTEXT = {

    "commit/",
    "checksum",
    "sha1",
    "sha256",
    "integrity",
    "node_modules",
    "package-lock.json",
    "yarn.lock",
}


def shannon_entropy(data):

    entropy = 0

    for x in set(data):

        p_x = float(data.count(x)) / len(data)

        entropy -= p_x * math.log2(p_x)

    return entropy


def looks_like_secret(token, text):

    if len(token) < 24:
        return False

    if re.fullmatch(r"[a-f0-9]{40}", token):
        return False

    if re.fullmatch(r"[a-f0-9]{64}", token):
        return False

    if shannon_entropy(token) < 4.5:
        return False

    text_lower = text.lower()

    if not any(k in text_lower for k in CONTEXT_KEYWORDS):
        return False

    if any(ignore in text_lower for ignore in IGNORED_CONTEXT):
        return False

    return True


####################################
# SECRET PATTERNS
####################################

SECRET_PATTERNS = {

    "AWS_ACCESS_KEY":
        r"(AKIA[0-9A-Z]{16})",

    "GITHUB_PAT":
        r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,})",

    "JWT":
        r"(eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)",

    "STRIPE_SECRET":
        r"(sk_live_[0-9a-zA-Z]{24})",

    "SLACK_WEBHOOK":
        r"(https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+)",

    "DISCORD_WEBHOOK":
        r"(https:\/\/discord\.com\/api\/webhooks\/[A-Za-z0-9\/]+)",

    "API_KEY":
        r"(api[_-]?key)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{20,})[\"']",
}


####################################
# DEDUP ENGINE
####################################

def already_reported(secret):

    if secret in printed_secrets:
        return True

    printed_secrets.add(secret)

    return False


####################################
# SAFE PRINT
####################################

def safe_print(msg):

    with print_lock:
        print(msg)


####################################
# OUTPUT
####################################

def print_finding(repo_url,
                  branch,
                  commit_hash,
                  file_path,
                  secret_type,
                  secret_value):

    global global_findings

    if already_reported(secret_value):
        return

    global_findings += 1

    repo_clean = repo_url.replace(".git", "")

    link = (

        f"{repo_clean}/blob/{commit_hash}/{file_path}"

        if commit_hash

        else

        f"{repo_clean}/blob/{branch}/{file_path}"

    )

    safe_print(f"""
🚨 SECRET FOUND [{secret_type}]
Repo: {repo_clean}
Branch: {branch}
Commit: {commit_hash if commit_hash else "LATEST"}
File: {file_path}
Link: {link}
Value: {secret_value[:80]}
------------------------------------------------------------
""")


####################################
# ENTROPY SCAN
####################################

ENTROPY_REGEX = re.compile(r"[A-Za-z0-9+/=_-]{24,}")


def entropy_scan(text,
                 repo_url,
                 branch,
                 commit_hash,
                 file_path):

    findings = 0

    matches = ENTROPY_REGEX.findall(text)

    for token in matches:

        if not looks_like_secret(token, text):
            continue

        print_finding(
            repo_url,
            branch,
            commit_hash,
            file_path,
            "HIGH_ENTROPY_SECRET",
            token
        )

        findings += 1

    return findings


####################################
# TEXT SCANNER
####################################

def scan_text(text,
              repo_url,
              branch,
              commit_hash,
              file_path):

    findings = 0

    for secret_type, pattern in SECRET_PATTERNS.items():

        matches = re.findall(pattern, text)

        for match in matches:

            if isinstance(match, tuple):
                match = match[-1]

            print_finding(
                repo_url,
                branch,
                commit_hash,
                file_path,
                secret_type,
                match
            )

            findings += 1

    findings += entropy_scan(
        text,
        repo_url,
        branch,
        commit_hash,
        file_path
    )

    return findings


####################################
# PEOPLE DISCOVERY
####################################

def add_user(user):

    if user and user not in discovered_users:

        discovered_users.add(user)

        return True

    return False


def get_org_members(org):

    return [

        m["login"]

        for m in paginate(
            f"https://api.github.com/orgs/{org}/members"
        )
    ]


def get_repo_contributors(owner, repo):

    return [

        c["login"]

        for c in paginate(
            f"https://api.github.com/repos/{owner}/{repo}/contributors"
        )
    ]


####################################
# COMMIT HISTORY
####################################

def scan_commit_history(repo,
                        repo_url,
                        branch):

    findings = 0

    for commit in repo.iter_commits(branch.name):

        commit_hash = commit.hexsha

        for file_path in commit.stats.files:

            try:

                blob = commit.tree / file_path

                content = blob.data_stream.read().decode(
                    "utf-8",
                    errors="ignore"
                )

                findings += scan_text(
                    content,
                    repo_url,
                    branch.name,
                    commit_hash,
                    file_path
                )

            except:

                continue

    return findings


####################################
# BRANCH SCAN
####################################

def scan_branch(repo,
                repo_url,
                branch):

    findings = 0

    repo.git.checkout(branch)

    for root, _, files in os.walk(repo.working_tree_dir):

        for file in files:

            path = os.path.join(root, file)

            relative = path.replace(
                repo.working_tree_dir + "/",
                ""
            )

            try:

                with open(path,
                          "r",
                          errors="ignore") as f:

                    findings += scan_text(
                        f.read(),
                        repo_url,
                        branch.name,
                        None,
                        relative
                    )

            except:

                continue

    if SCAN_HISTORY:

        findings += scan_commit_history(
            repo,
            repo_url,
            branch
        )

    return findings


####################################
# REPO SCAN
####################################

def scan_repo(repo_url):

    if repo_url in scanned_repos:
        return 0

    scanned_repos.add(repo_url)

    safe_print(f"\n🔍 START repo: {repo_url}")

    owner = repo_url.split("github.com/")[1].split("/")[0]

    repo_name = repo_url.split("/")[-1].replace(".git", "")

    repo_path = f"{WORKDIR}/{repo_name}"

    try:

        repo = Repo.clone_from(repo_url,
                               repo_path)

    except:

        safe_print(f"❌ clone failed: {repo_url}")

        return 0

    try:

        contributors = get_repo_contributors(
            owner,
            repo_name
        )

        for contributor in contributors:

            add_user(contributor)

    except:

        pass

    repo_findings = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:

        futures = [

            executor.submit(
                scan_branch,
                repo,
                repo_url,
                branch
            )

            for branch in repo.branches
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
# GITHUB API HELPERS
####################################

def github_api(url):

    r = requests.get(url,
                     headers=HEADERS)

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

    return [

        r["clone_url"]

        for r in paginate(
            f"https://api.github.com/orgs/{org}/repos"
        )
    ]


def get_user_repos(user):

    return [

        r["clone_url"]

        for r in paginate(
            f"https://api.github.com/users/{user}/repos"
        )
    ]


####################################
# MAIN
####################################

def main():

    os.makedirs(WORKDIR,
                exist_ok=True)

    repos = set()

    users = set()

    if TARGET_TYPE == "org":

        repos.update(get_org_repos(TARGET_NAME))

        members = get_org_members(TARGET_NAME)

        users.update(members)

    elif TARGET_TYPE == "user":

        users.add(TARGET_NAME)

    for user in users:

        repos.update(get_user_repos(user))

    safe_print(
        f"\n🚀 Exposure-surface scan starting ({len(repos)} repos)\n"
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:

        executor.map(scan_repo,
                     repos)

    safe_print(f"""
🎯 SCAN COMPLETE
Unique secrets detected: {global_findings}
Users discovered: {len(discovered_users)}
""")


if __name__ == "__main__":
    main()
