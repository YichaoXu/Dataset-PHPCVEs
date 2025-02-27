import re
import json
from typing import Dict, Optional
from utils.logger import Logger
from config import config
from utils.github import GitHubAPI
from cwe_tree import query as cwe_query

class CVEProcessor:
    """CVE data processing and extraction"""
    def __init__(self, github_api: GitHubAPI):
        self.github_api = github_api

    def process_cve(self, data: Dict) -> Optional[Dict]:
        try:
            if not self._is_php_related(data):
                return None

            cve_id = data.get('cveMetadata', {}).get('cveId')
            cwe_type = self._extract_cwe(data)
            if not cwe_type:
                return None

            commit_info = self._extract_github_commit(data)
            if not commit_info:
                return None

            return {
                'cve_id': cve_id,
                'cwe_type': cwe_type,
                **commit_info
            }
        except Exception as e:
            Logger.error(f"Failed to process CVE: {e}")
            return None

    def _is_php_related(self, data: Dict) -> bool:
        content = json.dumps(data).lower()
        return any(kw in content for kw in config.php_keywords)

    def _extract_cwe(self, data: Dict) -> str:
        """Extract CWE type with multiple fallback mechanisms"""
        if data.get("cveMetadata", {}).get("state", "") == "REJECTED":
            return "UNKNOWN"
        
        cwe_ids = set()
        
        # 1. Extract from problemTypes
        for entry in data.get("containers", {}).get("cna", {}).get("problemTypes", []):
            for desc in entry.get("descriptions", []):
                if "CWE" in desc.get("type", "").upper():
                    cwe_id = desc.get("cweId")
                    if cwe_id:
                        cwe_ids.add(cwe_id)
        
        # 2. Extract from references
        for ref in data.get("containers", {}).get("cna", {}).get("references", []):
            url = ref.get("url", "").upper()
            if "CWE" in url:
                matches = re.findall(r'CWE-\d+', url)
                cwe_ids.update(matches)
        
        # 3. Extract from description
        if not cwe_ids:
            description = str(data.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value", ""))
            cwe_matches = re.findall(r'CWE-\d+', description)
            cwe_ids.update(cwe_matches)
        
        if not cwe_ids:
            return "UNKNOWN"
        
        # Get valid CWE nodes
        valid_nodes = {}
        for cwe_id in cwe_ids:
            try:
                node = cwe_query.get_node(cwe_id)
                if node is not None:
                    valid_nodes[cwe_id] = node
            except Exception as e:
                Logger.error(f"Error getting CWE node for {cwe_id}: {e}")
        
        if not valid_nodes:
            return "UNKNOWN"
        
        try:
            id_max_map = {cwe_id: max((l for l in node.layer.values()), default=-1) 
                          for cwe_id, node in valid_nodes.items()}
            return max(valid_nodes.keys(), key=lambda cwe_id: id_max_map[cwe_id])
        except Exception as e:
            Logger.error(f"Error processing CWE nodes: {e}")
            return next(iter(valid_nodes.keys()), "UNKNOWN")

    def _extract_github_commit(self, data: Dict) -> Optional[Dict]:
        for ref in data.get("containers", {}).get("cna", {}).get("references", []):
            url = ref.get("url", "")
            if not url or "github.com" not in url:
                continue

            # Skip non-commit URLs
            if any(skip in url for skip in ["/compare/", "/issues/", "/pull/", "/tree/"]):
                Logger.warning(f"Skipping non-commit URL: {url}")
                continue

            match = re.search(
                r"github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]{7,40})",
                url
            )
            if not match:
                continue
            
            owner, repo, commit_sha = match.groups()
            
            # Add failure count
            failure_count = 0
            while failure_count < 3:
                commit_data = self.github_api.get_commit_details(owner, repo, commit_sha)
                if commit_data:
                    break
                failure_count += 1
                time.sleep(5)
            
            if failure_count >= 3:
                Logger.error(f"Skipping {url} after multiple failures")
                continue

            # Check for PHP files
            files = commit_data.get("files", [])
            if not any(file["filename"].endswith('.php') for file in files):
                continue

            # Get parent commit
            parents = commit_data.get("parents", [])
            if not parents:
                continue

            # Infer project type
            project_type = self.github_api.infer_project_type(owner, repo)

            return {
                "repository": f"https://github.com/{owner}/{repo}",
                "current_commit": commit_sha,
                "previous_commit": parents[0]["sha"],
                "project_type": project_type
            }

        return None 