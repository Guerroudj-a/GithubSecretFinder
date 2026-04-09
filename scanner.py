import os
import re
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
INCLUDE_MEMBERS = os.getenv("INCLUDE_MEMBERS") == "true"

HEADERS = {"Authorization": f"token {TOKEN}"}

WORKDIR = "repos"

print_lock = Lock()

global_findings = 0


####################################
# HIGH-SIGNAL SECRET PATTERNS
####################################

SECRET_PATTERNS = {

    "AWS_ACCESS_KEY_ID":
        r"AWS_ACCESS_KEY_ID\s*=\s*[\"']?(AKIA[0-9A-Z]{16})",

    "AWS_SECRET_ACCESS_KEY":
        r"AWS_SECRET_ACCESS_KEY\s*=\s*[\"']?([A-Za-z0-9\/+=]{40})",

    "AWS_CONFIGURE_CMD":
        r"aws\s+configure\s+set\s+(aws_access_key_id|aws_secret_access_key)",

    "DOCKER_LOGIN":
        r"docker\s+login\s+-u\s+\S+\s+-p\s+\S+",

    "DOCKER_CONFIG_AUTH":
        r'"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})"',

    "GITHUB_PAT":
        r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,})",

    "ARGOCD_LOGIN":
        r"argocd\s+login\s+\S+\s+--username\s+\S+\s+--password\s+\S+",

    "KUBECONFIG_TOKEN":
        r"token:\s+([A-Za-z0-9\.\-_]{20,})",

    "KUBE_BEARER":
        r"Authorization:\s*Bearer\s+([A-Za-z0-9\.\-_]{20,})",

    "DATABASE_URL":
        r"(postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^@\s]+",

    "STRIPE_SECRET":
        r"(sk_live_[0-9a-zA-Z]{24})",

    "SLACK_WEBHOOK":
        r"(https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+)",

    "DISCORD_WEBHOOK":
        r"(https:\/\/discord\.com\/api\/webhooks\/[A-Za-z0-9\/]+)",

    "BASIC_AUTH_URL":
        r"https?:\/\/([^:\s]+):([^@\s]+)@([^\s]+)"
}


####################################
# FALSE POSITIVE FILTERS
####################################

INVALID_VALUES = {

    "",
    "example",
    "changeme",
    "your_token_here",
    "password",
    "secret",
    "null",
    "none"
}


INVALID_USERS = {

    "user",
    "username",
    "admin",
    "example",
    "test",
    "demo",
    "root"
}


INVALID_PASSWORDS = {

    "password",
    "passwd",
    "example",
    "test",
    "changeme",
    "123456",
    "admin"
}


INVALID_HOSTS = {

    "localhost",
    "127.0.0.1",
    "0.0.0.0"
}


####################################
# VALIDATORS
####################################

def is_valid_secret(value):

    if not value:
        return False

    if value.lower() in INVALID_VALUES:
        return False

    if len(value) < 12:
        return False

    return True


def is_valid_basic_auth(user, password, host):

    if user.lower() in INVALID_USERS:
        return False

    if password.lower() in INVALID_PASSWORDS:
        return False

    if len(password) < 8:
        return False

    if any(h in host.lower() for h in INVALID_HOSTS):
        return False

    return True


####################################
# THREAD SAFE PRINT
####################################

def safe_print(message):

    with print_lock:
        print(message)


####################################
# OUTPUT FORMATTER
####################################

def print_finding(repo_url, branch, commit_hash,
                  file_path, secret_type, match):

    global global_findings

    global_findings += 1

    repo_clean = repo_url.replace(".git", "")

    if commit_hash:

        link = f"{repo_clean}/blob/{commit_hash}/{file_path}"

    else:

        link = f"{repo_clean}/blob/{branch}/{file_path}"

    safe_print(f"""
🚨 SECRET FOUND [{secret_type}]
Repo: {repo_clean}
Branch: {branch}
Commit: {commit_hash if commit_hash else "LATEST"}
File: {file_path}
Link: {link}
Value: {match[:80]}
------------------------------------------------------------
""")


####################################
# TEXT SCANNER
####################################

def scan_text(text, repo_url,
              branch, commit_hash,
              file_path):

    findings = 0

    for secret_type, pattern in SECRET_PATTERNS.items():

        matches = re.findall(pattern, text)

        for match in matches:

            if secret_type == "BASIC_AUTH_URL":

                user, password, host = match

                if not is_valid_basic_auth(
                        user,
                        password,
                        host):

                    continue

                match = f"{user}:***@{host}"

            else:

                if isinstance(match, tuple):

                    match = match[0]

                if not is_valid_secret(match):

                    continue

            findings += 1

            print_finding(
                repo_url,
                branch,
                commit_hash,
                file_path,
                secret_type,
                match
            )

    return findings


####################################
# COMMIT HISTORY SCANNER
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

        repo = Repo.clone_from(
            repo_url,
            repo_path,
            depth=None if SCAN_HISTORY else 1
        )

    except:

        safe_print(
            f"❌ clone failed: {repo_url}"
        )

        return 0

    branches = (
        repo.branches
        if SCAN_BRANCHES
        else [repo.active_branch]
    )

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
# GITHUB API HELPERS
####################################

def github_api(url):

    response = requests.get(
        url,
        headers=HEADERS
    )

    if response.status_code != 200:

        return []

    return response.json()


def paginate(url):

    results = []

    page = 1

    while True:

        data = github_api(
            f"{url}?page={page}"
        )

        if not data:

            break

        results.extend(data)

        page += 1

    return results


def get_org_repos(org):

    repos = paginate(
        f"https://api.github.com/orgs/{org}/repos"
    )

    return [

        repo["clone_url"]

        for repo in repos
    ]


def get_user_repos(user):

    repos = paginate(
        f"https://api.github.com/users/{user}/repos"
    )

    return [

        repo["clone_url"]

        for repo in repos
    ]


def get_org_members(org):

    members = paginate(
        f"https://api.github.com/orgs/{org}/members"
    )

    return [

        member["login"]

        for member in members
    ]


####################################
# MAIN EXECUTION
####################################

def main():

    os.makedirs(
        WORKDIR,
        exist_ok=True
    )

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

            if INCLUDE_MEMBERS:

                members = get_org_members(
                    TARGET_NAME
                )

                for member in members:

                    repos.extend(
                        get_user_repos(
                            member
                        )
                    )

        elif TARGET_TYPE == "user":

            repos.extend(
                get_user_repos(
                    TARGET_NAME
                )
            )

    safe_print(
        f"\n🚀 Deep credential scan starting ({len(repos)} repos)\n"
    )

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(8, len(repos))) as executor:

        executor.map(
            scan_repo,
            repos
        )

    safe_print(f"""
🎯 SCAN COMPLETE
Total verified secrets detected: {global_findings}
""")


if __name__ == "__main__":
    main()
