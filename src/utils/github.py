"""
GitHub API client for PHP CVE Dataset Collection Tool.

This module provides functionality to interact with the GitHub API,
retrieve repository information, and download code.
"""

import time
import requests
import re
import os
from typing import Dict, Optional, Any
from src.config import config
from src.utils.logger import Logger
from src.utils.error_handler import ErrorHandler

class GitHubAPI:
    """GitHub API client for retrieving repository information."""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: Optional[str] = None):
        """
        Initialize the GitHub API client.
        
        Args:
            token: GitHub API token
        """
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.headers = {
            "Accept": "application/vnd.github.v3+json"
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"
        else:
            Logger.warning("No GitHub token provided. API rate limits will be severely restricted.")
    
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
            url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{commit_hash}"
            response = self.get(url)
            
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
            url = f"{self.BASE_URL}/repos/{owner}/{repo}"
            return self.get(url) or {}
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
        
        # Validate commit SHA format
        if not re.match(r'^[0-9a-f]{7,40}$', commit_sha, re.IGNORECASE):
            # Log to file only, don't print to console
            Logger.debug(f"Invalid commit SHA format: {commit_sha}")
            return None
        
        # Make API request
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{commit_sha}"
        
        try:
            response = self.get(url)
            if not response:
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

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Make a GET request to the GitHub API."""
        url = f"{self.BASE_URL}/{endpoint}"
        
        for attempt in range(config.api_retry_count + 1):
            try:
                response = requests.get(url, headers=self.headers, params=params)
                
                if response.status_code == 200:
                    return response.json()
                
                if response.status_code == 403 and config.github_rate_limit_wait:
                    # Rate limited, get reset time and wait
                    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                    wait_time = max(0, reset_time - time.time()) + 1
                    
                    if wait_time > 0 and wait_time < 3600:  # Don't wait more than an hour
                        Logger.warning(f"Rate limited. Waiting {wait_time:.0f} seconds...")
                        time.sleep(wait_time)
                        continue
                
                Logger.error(f"GitHub API error: {response.status_code} - {response.text}")
                return None
                
            except Exception as e:
                Logger.error(f"Error making request to GitHub API: {str(e)}")
                
                if attempt < config.api_retry_count:
                    wait_time = config.api_retry_delay * (attempt + 1)
                    Logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    return None
        
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