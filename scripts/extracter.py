import argparse, csv, re, os, json, time, random, requests
from cwe_tree import query as cwe_query

# **Parse command-line arguments**
def parse_args():
    parser = argparse.ArgumentParser(description="Extract PHP-related CVEs from JSON files")
    parser.add_argument("input_dir", type=str, help="Directory containing CVE JSON files")
    parser.add_argument("--output-csv", type=str, default="dataset.csv", help="Output CSV filename")
    parser.add_argument("--filter-unknown", action="store_true", help="Exclude rows containing 'UNKNOWN'")
    parser.add_argument("--php-keywords", type=str, default="php,.php,zend,laravel,wordpress,drupal,joomla",
                        help="Comma-separated PHP-related keywords (use 'none' to disable filtering)")
    parser.add_argument("--exclude-keywords", type=str, default="php-src,plugin",
                        help="Comma-separated keywords to exclude (use 'none' to disable filtering)")
    args = parser.parse_args()
    
    args.php_keywords = [] if args.php_keywords.lower() == "none" else args.php_keywords.split(",")
    args.exclude_keywords = [] if args.exclude_keywords.lower() == "none" else args.exclude_keywords.split(",")
    
    return args

# **Extract CWE type**
def extract_cwe(data: dict):
    if data.get("cveMetadata", {}).get("state", "") == "REJECTED":
        return 
    
    cwe_ids = {desc.get("cweId", "UNKNOWN") for entry in data.get("containers", {}).get("cna", {}).get("problemTypes", [])
               for desc in entry.get("descriptions", []) if "CWE" in desc.get("type", "").upper()}
    
    cwe_nodes = {cwe_id: cwe_query.get_node(cwe_id) for cwe_id in cwe_ids}
    valid_nodes = {cwe_id: node for cwe_id, node in cwe_nodes.items() if node is not None}
    
    if not valid_nodes:
        return None
    
    id_max_map = {cwe_id: max((l for l in node.layer.values()), default=-1) for cwe_id, node in valid_nodes.items()}
    cwe_id = max(valid_nodes, key=lambda cwe_id: id_max_map[cwe_id])
    cwe_node = valid_nodes[cwe_id]
    
    return f"{cwe_node.cwe_id}: {cwe_node.name}"


def get_commit_parents_and_files(owner, repo, current_commit):
    """
    Get the list of modified files and parent commits for a given commit,
    using GitHub API with authentication and retry mechanism.

    :param owner: GitHub repository owner
    :param repo: GitHub repository name
    :param current_commit: The commit SHA to check
    :return: A tuple (parent commits list, modified files list)
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{current_commit}"
    headers:dict = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "MyGitHubClient"  # Prevents 403 errors
    }
    token = os.getenv("GITHUB_TOKEN", None)  # Fetch from environment variable
    if token is not None: headers["Authorization"] = f"token {token}"

    retry_attempts = 0
    delay = 2

    while retry_attempts < 2:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            commit_data = response.json()
            cmt_parents = [parent["sha"] for parent in commit_data.get("parents", [])]
            changed_files = [file["filename"] for file in commit_data.get("files", [])]
            return cmt_parents, changed_files  # ✅ Success, return data
        elif response.status_code == 403:
            # Rate limit exceeded, check remaining limit
            limit_response = requests.get(f"https://api.github.com/repos/rate_limit", headers=headers)
            remaining = limit_response.json().get("rate", {}).get("remaining", 0)
            reset_time = limit_response.json().get("rate", {}).get("reset", time.time())

            if remaining == 0:
                wait_time = int(reset_time - time.time()) + 1
                print(f"🚦 Rate limit exceeded. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue  # Retry after waiting
        elif response.status_code in {500, 502, 503, 504}:
            # GitHub service errors, retry with exponential backoff
            print(f"⚠️ GitHub server error {response.status_code}. Retrying in {delay}s...")
            time.sleep(delay + random.uniform(0, 1))  # Add slight jitter
            delay *= 2  # Exponential backoff
            retry_attempts += 1
            continue
        else:
            # Other errors, print message and return empty lists
            print(f"❌ Failed to fetch commit details ({response.status_code}): {response.text}")
            return [], []

    print(f"🚫 Max retries reached for commit {current_commit}. Skipping...")
    return [], []  # Return empty lists on failure


def is_php_filename(filename):
    return re.search(r"\.(phps?|php[3457]?|phtml|inc)$", str(filename), re.IGNORECASE) is not None

# **Extract the first GitHub commit URL and its previous commit**
def extract_github_commit(data):
    references = data.get("containers", {}).get("cna", {}).get("references", [])
    for ref in references:
        url = ref.get("url", None) 
        if url is None: continue
        match = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]{7,40})", url)
        if not match: continue
        owner, repo, commit_sha = match.groups()
        (cmt_parents, cmt_files) = get_commit_parents_and_files(owner, repo, commit_sha)
        if not cmt_parents or not any(is_php_filename(file) for file in cmt_files): continue
        return {"repository": f"https://github.com/{owner}/{repo}", "current_commit": commit_sha, "previous_commit": cmt_parents[0]}
    return {"repository": None, "current_commit": None, "previous_commit": None}

def is_php_related(data, php_keywords, exclude_keywords):
    content = json.dumps(data).lower()
    if php_keywords and not any(kw in content for kw in php_keywords):
        return False
    if exclude_keywords and any(ex_kw in content for ex_kw in exclude_keywords):
        return False
    return True

# **Process JSON files and filter PHP-related vulnerabilities**
def find_php_vulnerabilities(directory, php_keywords, exclude_keywords, filter_unknown):
    php_vulnerabilities = []
    error_log = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.startswith("CVE-") and file.endswith(".json"):
                file_path = os.path.join(root, file)
                cve_id = os.path.splitext(file)[0]
                
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if not is_php_related(data, php_keywords, exclude_keywords):
                            continue
                        
                        cwe_str = extract_cwe(data)
                        github_commits = extract_github_commit(data)
                        
                        if filter_unknown and (cwe_str is None or None in github_commits.values()): continue
                        php_vulnerabilities.append([cve_id, cwe_str, *github_commits.values()])
                except Exception as e:
                    error_log.append(f"{file_path}: {str(e)}")
    
    if error_log:
        print("⚠️ The following files could not be parsed:")
        for log in error_log:
            print(log)
    
    return php_vulnerabilities

# **Save extracted data to CSV**
def save_to_csv(data, output_file):
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["CVE ID", "CWE Type", "Current Commit", "Previous Commit"])
            writer.writerows(data)
        print(f"✅ Results saved to {output_file}, total {len(data)} records.")
    except IOError as e:
        print(f"❌ Failed to write CSV: {e}")

# **Main function**
def main():
    args = parse_args()
    php_vulns = find_php_vulnerabilities(
        args.input_dir,
        args.php_keywords,
        args.exclude_keywords,
        args.filter_unknown,
    )
    
    if php_vulns:
        save_to_csv(php_vulns, args.output_csv)
    else:
        print("❌ No matching CVEs found.")

if __name__ == "__main__":
    main()
