import time
import random
import requests
import re
from typing import Dict, Optional, Any
from src.config import config
from src.utils.logger import Logger
from src.utils.error_handler import ErrorHandler

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
            parts = repo_path.split('/')
            if len(parts) < 2:
                Logger.warning(f"Invalid repository URL format: {repo_url}")
                return None
                
            owner, repo = parts[0], parts[1]
            
            # Get commit details
            url = f"{self.base_url}/repos/{owner}/{repo}/commits/{commit_hash}"
            response = self._make_request(url)
            
            if not response:
                return None
                
            parents = response.get("parents", [])
            
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
            parts = repo_path.split('/')
            if len(parts) < 2:
                return {}
                
            owner, repo = parts[0], parts[1]
            
            # Get repo details
            url = f"{self.base_url}/repos/{owner}/{repo}"
            return self._make_request(url) or {}
        except Exception as e:
            Logger.warning(f"Failed to get repo info: {str(e)}")
            return {}

    def get_commit_details(self, owner: str, repo: str, commit_sha: str) -> Optional[Dict[str, Any]]:
        """
        Get details of a specific commit.
        
        Args:
            owner: Repository owner
            repo: Repository name
            commit_sha: Commit SHA
            
        Returns:
            Commit details or None if not found
        """
        # Validate inputs
        if not owner or not repo or not commit_sha:
            # Log to file only, don't print to console
            Logger.debug(f"Invalid parameters for get_commit_details: owner={owner}, repo={repo}, commit_sha={commit_sha}")
            return None
        
        # Normalize inputs
        owner = owner.strip()
        repo = repo.strip()
        commit_sha = commit_sha.strip()
        
        # Validate commit SHA format
        if not re.match(r'^[0-9a-f]{7,40}$', commit_sha, re.IGNORECASE):
            # Log to file only, don't print to console
            Logger.debug(f"Invalid commit SHA format: {commit_sha}")
            return None
        
        url = f"{self.base_url}/repos/{owner}/{repo}/commits/{commit_sha}"
        
        try:
            # The _make_request method already returns the JSON data, not the Response object
            response = self._make_request(url)
            
            # If response is None, the request failed
            if response is None:
                # Log to file only, don't print to console
                Logger.debug(f"Commit not found: {owner}/{repo}/{commit_sha}")
                return None
            
            # Return the response directly since it's already the JSON data
            return response
        except Exception as e:
            # Log to file only, don't print to console
            Logger.debug(f"Error getting commit details: {str(e)}")
            return None

    def _handle_rate_limit(self, response: requests.Response) -> int:
        """Handle rate limiting and return wait time in seconds."""
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
        """Make a request to the GitHub API with retries and error handling."""
        retry_attempts = 0
        max_retries = 5
        base_delay = 2
        
        # Extract repo info from URL for better error messages
        repo_info = "unknown"
        if "/repos/" in url:
            parts = url.split("/repos/")[1].split("/")
            if len(parts) >= 2:
                repo_info = f"{parts[0]}/{parts[1]}"
        
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
                    # For 404 errors, just log to file, don't print to console
                    if response.status_code == 404:
                        Logger.debug(f"API request failed for {repo_info}: 404 Not Found")
                    else:
                        # For other errors, log with higher severity but still avoid console
                        Logger.debug(f"API request failed for {repo_info}: {response.status_code}")
                    return None
            except Exception as e:
                # Log to file only, don't print to console
                Logger.debug(f"Request error for {repo_info}: {e}")
                retry_attempts += 1
                time.sleep(base_delay * (2 ** retry_attempts))
        return None

    def get_readme(self, owner: str, repo: str) -> Optional[str]:
        """Get repository README content."""
        return ErrorHandler.with_retry(
            self._get_readme_internal,
            owner,
            repo,
            error_msg=f"Failed to get README for {owner}/{repo}"
        )
    
    def _get_readme_internal(self, owner: str, repo: str) -> Optional[str]:
        """Internal method to get README content."""
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
        """Infer project type from repository name and README content."""
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