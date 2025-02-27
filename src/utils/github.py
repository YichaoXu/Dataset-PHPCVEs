import time
import random
import requests
from typing import Dict, Optional
from config import config
from utils.logger import Logger

class GitHubAPI:
    """GitHub API client for retrieving repository information."""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github.v3+json"
        }
        if token:
            self.headers["Authorization"] = f"token {token}"
    
    def get_previous_commit(self, repo_url: str, commit_hash: str) -> Optional[str]:
        """Get the parent commit hash for a given commit."""
        try:
            # Extract owner and repo from URL
            repo_path = repo_url.replace("https://github.com/", "")
            owner, repo = repo_path.split("/")
            
            # Get commit details
            url = f"{self.base_url}/repos/{owner}/{repo}/commits/{commit_hash}"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            parents = data.get("parents", [])
            
            if parents:
                return parents[0].get("sha")
            
            return None
        except Exception as e:
            Logger.warning(f"Failed to get previous commit: {str(e)}")
            return None
    
    def get_repo_info(self, repo_url: str) -> dict:
        """Get repository information."""
        try:
            # Extract owner and repo from URL
            repo_path = repo_url.replace("https://github.com/", "")
            owner, repo = repo_path.split("/")
            
            # Get repo details
            url = f"{self.base_url}/repos/{owner}/{repo}"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
        except Exception as e:
            Logger.warning(f"Failed to get repo info: {str(e)}")
            return {}

    def get_commit_details(self, owner: str, repo: str, commit_sha: str) -> Optional[Dict]:
        url = f"{config.github_api_url}/repos/{owner}/{repo}/commits/{commit_sha}"
        return self._make_request(url)

    def _handle_rate_limit(self, response: requests.Response) -> int:
        """Handle rate limiting and return wait time in seconds"""
        try:
            # Get reset time from response headers
            reset_time = response.headers.get('X-RateLimit-Reset')
            remaining = response.headers.get('X-RateLimit-Remaining', '0')
            limit = response.headers.get('X-RateLimit-Limit', '60')
            
            if reset_time:
                current_time = int(time.time())
                wait_time = max(int(reset_time) - current_time + 1, 60)
                
                # Add extra wait time if close to limit
                if int(remaining) < int(limit) * 0.1:  # Less than 10% remaining
                    wait_time += 30
                    
                Logger.warning(f"Rate limit: {remaining}/{limit}. Waiting {wait_time} seconds...")
                return wait_time
        except Exception as e:
            Logger.error(f"Error handling rate limit: {e}")
            return 3600  # Default wait 1 hour on error

    def _make_request(self, url: str) -> Optional[Dict]:
        retry_attempts = 0
        max_retries = 5
        base_delay = 2
        
        while retry_attempts < max_retries:
            try:
                response = requests.get(url, headers=self.headers)
                if response.status_code == 200:
                    return response.json()
                elif response.status_code in {403, 429}:
                    wait_time = self._handle_rate_limit(response)
                    time.sleep(wait_time)
                    continue
                elif response.status_code in {500, 502, 503, 504}:
                    retry_attempts += 1
                    delay = base_delay * (2 ** retry_attempts) + random.uniform(0, 1)
                    time.sleep(min(delay, 300))
                else:
                    Logger.error(f"API request failed: {response.status_code}")
                    return None
            except Exception as e:
                Logger.error(f"Request error: {e}")
                retry_attempts += 1
                time.sleep(base_delay * (2 ** retry_attempts))
        return None

    def get_readme(self, owner: str, repo: str) -> Optional[str]:
        """Get repository README content"""
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/README.md"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.text
            
            # Try master branch if main doesn't exist
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/README.md"
            response = requests.get(url)
            if response.status_code == 200:
                return response.text
            
            return None
        except Exception:
            return None

    def infer_project_type(self, owner: str, repo: str) -> str:
        """Infer project type from repository name and README content"""
        # Check known projects first
        repo_lower = repo.lower()
        for known_name, project_type in config.known_projects.items():
            if known_name in repo_lower:
                return project_type
            
        # Get README content
        readme = self.get_readme(owner, repo)
        if not readme:
            return "Unknown"

        readme_lower = readme.lower()
        type_scores = {ptype: 0 for ptype in config.project_types.keys()}

        # Calculate weighted scores
        for ptype, keywords in config.project_types.items():
            for keyword, weight in keywords.items():
                count = readme_lower.count(keyword)
                type_scores[ptype] += count * weight

        # Get the type with highest score
        max_score = max(type_scores.values())
        if max_score == 0:
            return "Unknown"

        # If multiple types have the same score, prefer more specific types
        candidates = [t for t, s in type_scores.items() if s == max_score]
        priority = ['PHP-SRC', 'Framework Plugin', 'Framework Theme', 'Web App', 'CLI App', 'Library']
        for p in priority:
            if p in candidates: return p

        return candidates[0] 