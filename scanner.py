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

HEADERS = {"Authorization": f"token {TOKEN}"}

WORKDIR = "repos"

print_lock = Lock()

global_findings = 0
printed_secrets = set()


####################################
# ENTROPY DETECTOR
####################################

CONTEXT_KEYWORDS = {

    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
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
    "pnpm-lock.yaml",
}

def shannon_entropy(data):

    if not data:
        return 0

    entropy = 0

    for x in set(data):

        p_x = float(data.count(x)) / len(data)

        entropy -= p_x * math.log2(p_x)

    return entropy


def looks_like_secret(token, text):

    if len(token) < 24:
        return False

    if token.startswith("sha"):
        return False

    if re.fullmatch(r"[a-f0-9]{40}", token):
        return False

    if re.fullmatch(r"[a-f0-9]{64}", token):
        return False

    entropy = shannon_entropy(token)

    if entropy < 4.5:
        return False

    lower_text = text.lower()

    if not any(keyword in lower_text for keyword in CONTEXT_KEYWORDS):
        return False

    if any(ignore in lower_text for ignore in IGNORED_CONTEXT):
        return False

    return True


####################################
# HIGH-SIGNAL REGEX PATTERNS
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

    "API_KEY_ASSIGNMENT":
        r"(api[_-]?key)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{20,})[\"']",

}


####################################
# FILTERS
####################################

INVALID_VALUES = {

    "",
    "example",
    "changeme",
    "password",
    "secret",
    "null",
    "none"
}


def is_valid_secret(value):

    if not value:
        return False

    if value.lower() in INVALID_VALUES:
        return False

    if len(value) < 12:
        return False

    return True


####################################
# DEDUP ENGINE
####################################

def already_reported(secret):

    if secret in printed_secrets:
        return True

    printed_secrets.add(secret)

    return False


####################################
# OUTPUT
####################################

def safe_print(msg):

    with print_lock:
        print(msg)


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
# ENTROPY TOKEN SCANNER
####################################

ENTROPY_REGEX = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


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

            if not is_valid_secret(match):
                continue

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
# HISTORY SCANNER
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
# BRANCH SCANNER
####################################

def scan_branch(repo,
                repo_url,
                branch):

    findings = 0

    repo.git.checkout(branch)

    for root, _, files in os.walk(
            repo.working_tree_dir):

        for file in files:

            path = os.path.join(root, file)

            relative_path = path.replace(
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
                        relative_path
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
# REPO SCANNER
####################################

def scan_repo(repo_url):

    safe_print(
        f"\n🔍 START repo: {repo_url}"
    )

    repo_name = repo_url.split("/")[-1].replace(".git", "")

    repo_path = f"{WORKDIR}/{repo_name}"

    try:

        repo = Repo.clone_from(repo_url,
                               repo_path)

    except:

        safe_print(
            f"❌ clone failed: {repo_url}"
        )

        return 0

    branches = repo.branches

    repo_findings = 0

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=4) as executor:

        futures = [

            executor.submit(
                scan_branch,
                repo,
                repo_url,
                branch
            )

            for branch in branches
        ]

        for future in concurrent.futures.as_completed(
                futures):

            repo_findings += future.result()

    safe_print(f"""
✅ FINISHED repo: {repo_url}
Secrets found: {repo_findings}
========================================
""")

    return repo_findings


####################################
# ENUMERATION
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

        repo["clone_url"]

        for repo in paginate(
            f"https://api.github.com/orgs/{org}/repos"
        )

    ]


def get_user_repos(user):

    return [

        repo["clone_url"]

        for repo in paginate(
            f"https://api.github.com/users/{user}/repos"
        )

    ]


####################################
# MAIN
####################################

def main():

    os.makedirs(WORKDIR,
                exist_ok=True)

    repos = []

    if REPO_NAME:

        repos = [

            f"https://github.com/{TARGET_NAME}/{REPO_NAME}.git"

        ]

    else:

        if TARGET_TYPE == "org":

            repos.extend(
                get_org_repos(
                    TARGET_NAME
                )
            )

        elif TARGET_TYPE == "user":

            repos.extend(
                get_user_repos(
                    TARGET_NAME
                )
            )

    safe_print(
        f"\n🚀 Entropy-enhanced credential scan starting ({len(repos)} repos)\n"
    )

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(8, len(repos))) as executor:

        executor.map(
            scan_repo,
            repos
        )

    safe_print(f"""
🎯 SCAN COMPLETE
Unique secrets detected: {global_findings}
""")


if __name__ == "__main__":
    main()
