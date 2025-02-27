import re
import json
import time
import csv
import os
from pathlib import Path
from collections import Counter
from typing import Dict, Optional, List, Any
from utils.logger import Logger
from config import config
from utils.github import GitHubAPI
from cwe_tree import query as cwe_query
from utils.file_utils import ensure_dir
from utils.error_handler import ErrorHandler
from models.cve import CVERecord

class CVEProcessor:
    """Processes CVE data to extract PHP-related vulnerabilities."""
    
    def __init__(self, github_api: GitHubAPI):
        self.github_api = github_api
        self.php_keywords = config.php_keywords
        self.error_handler = ErrorHandler()
    
    def process_cve_files(self, cve_dir: Path) -> List[CVERecord]:
        """Process all CVE JSON files in the directory."""
        records = []
        
        # Only process files that start with 'CVE-'
        json_files = []
        for file_path in cve_dir.rglob("*.json"):
            file_name = file_path.name
            if file_name.startswith("CVE-"):
                json_files.append(file_path)
        
        if not json_files:
            Logger.warning(f"No CVE JSON files found in {cve_dir}")
            return records
        
        Logger.info(f"Processing {len(json_files)} CVE records")
        
        # Create a custom progress callback that doesn't get interrupted by log messages
        import typer
        from rich.progress import Progress, TextColumn, BarColumn, TimeRemainingColumn, TaskProgressColumn
        
        # Process files with a better progress display
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            transient=False,  # Keep progress bar on screen
            refresh_per_second=1  # Lower refresh rate to reduce flicker
        ) as progress:
            task = progress.add_task("Processing CVEs", total=len(json_files))
            
            # Create a log buffer to collect messages during processing
            log_buffer = []
            
            for json_file in json_files:
                try:
                    # Try to read the file with multiple encodings
                    try:
                        content, _ = ErrorHandler.try_multiple_encodings(json_file)
                        data = json.loads(content)
                    except (UnicodeError, json.JSONDecodeError) as e:
                        log_buffer.append(f"Could not read file {json_file}: {str(e)}")
                        progress.update(task, advance=1)
                        continue
                    
                    # Process the CVE data
                    if record_dict := self.process_cve(data):
                        record = CVERecord.from_dict(record_dict)
                        records.append(record)
                except Exception as e:
                    log_buffer.append(f"Error processing file {json_file}: {str(e)}")
                
                # Update progress
                progress.update(task, advance=1)
        
        # After processing is complete, display the buffered log messages
        if log_buffer:
            Logger.info(f"Encountered {len(log_buffer)} issues during processing:")
            for i, message in enumerate(log_buffer[:10], 1):  # Show only first 10 errors
                Logger.warning(f"Issue {i}: {message}")
            
            if len(log_buffer) > 10:
                Logger.info(f"... and {len(log_buffer) - 10} more issues (see log file for details)")
                
                # Optionally write full log to file
                with open(cve_dir.parent / "processing_errors.log", "w") as f:
                    for message in log_buffer:
                        f.write(f"{message}\n")
        
        return records
    
    def process_cve(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a single CVE record to extract PHP-related vulnerability.
        
        Returns a dictionary with the following keys:
        - cve_id: The CVE identifier
        - cwe_type: The CWE type
        - repository: The GitHub repository URL
        - current_commit: The commit that fixed the vulnerability
        - previous_commit: The commit before the fix (vulnerable version)
        - project_type: The type of PHP project
        
        Returns None if the CVE is not PHP-related or doesn't have required information.
        """
        # Check if this is a PHP-related CVE
        if not self._is_php_related(data):
            return None
        
        # Extract CVE ID
        cve_id = data.get('cveMetadata', {}).get('cveId')
        if not cve_id:
            return None
        
        # Extract CWE type
        cwe_type = self._extract_cwe(data)
        
        # Extract GitHub repository and commit information
        repo_info = ErrorHandler.safe_execute(
            self._extract_repo_info, 
            data, 
            default_value=None
        )
        if not repo_info:
            return None
        
        # Determine project type
        project_type = ErrorHandler.safe_execute(
            self._determine_project_type, 
            repo_info['repository'], 
            default_value="Library"
        )
        
        return {
            'cve_id': cve_id,
            'cwe_type': cwe_type,
            'repository': repo_info['repository'],
            'current_commit': repo_info['current_commit'],
            'previous_commit': repo_info['previous_commit'],
            'project_type': project_type
        }
    
    def save_dataset(self, records: List[CVERecord], dataset_path: Path, cache_path: Path) -> bool:
        """Save the dataset to a CSV file and cache it."""
        try:
            fieldnames = ['cve_id', 'cwe_type', 'repository', 'current_commit', 'previous_commit', 'project_type']
            
            # Ensure directory exists
            ensure_dir(dataset_path.parent)
            
            # Convert records to dictionaries
            records_dicts = [record.to_dict() for record in records]
            
            with open(dataset_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(records_dicts)

            # Cache the dataset
            ensure_dir(cache_path.parent)
            from shutil import copy2
            copy2(dataset_path, cache_path)
            
            Logger.success(f"Found {len(records)} PHP-related CVEs")
            return True
        except Exception as e:
            Logger.error(f"Failed to save dataset: {str(e)}")
            return False
    
    def print_cwe_distribution(self, records: List[CVERecord]) -> None:
        """Print distribution of CWE types in the dataset."""
        if not records:
            return
        
        cwe_counts = Counter()
        for record in records:
            cwe_counts[record.cwe_type] += 1
        
        Logger.info("CWE Type Distribution:")
        for cwe, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True):
            Logger.info(f"  {cwe}: {count} CVEs")
    
    def _is_php_related(self, data: Dict[str, Any]) -> bool:
        """
        Check if a CVE is PHP-related by looking for PHP keywords in:
        1. Description
        2. References
        """
        # Check description for PHP keywords
        description = data.get('containers', {}).get('cna', {}).get('descriptions', [])
        if description:
            desc_text = description[0].get('value', '').lower()
            if any(keyword.lower() in desc_text for keyword in self.php_keywords):
                return True
        
        # Check references for PHP keywords
        references = data.get('containers', {}).get('cna', {}).get('references', [])
        for ref in references:
            url = ref.get('url', '').lower()
            if any(keyword.lower() in url for keyword in self.php_keywords):
                return True
        
        return False
    
    def _extract_cwe(self, data: Dict[str, Any]) -> str:
        """Extract CWE type from CVE data."""
        problems = data.get('containers', {}).get('cna', {}).get('problemTypes', [])
        if problems:
            descriptions = problems[0].get('descriptions', [])
            if descriptions:
                return descriptions[0].get('cweId', 'CWE-Other')
        
        return 'CWE-Other'
    
    def _extract_repo_info(self, data: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """
        Extract GitHub repository and commit information from CVE data.
        
        This method looks for GitHub commit URLs in the references and extracts:
        1. Repository URL
        2. Current commit (fix commit)
        3. Previous commit (vulnerable commit)
        
        If only the current commit is found, it tries to get the previous commit
        using the GitHub API.
        """
        references = data.get('containers', {}).get('cna', {}).get('references', [])
        
        commit_info = {'repository': None, 'current_commit': None, 'previous_commit': None}
        
        for ref in references:
            url = ref.get('url', '')
            if 'github.com' in url and '/commit/' in url:
                # Skip non-commit URLs
                if any(skip in url for skip in ["/compare/", "/issues/", "/pull/", "/tree/"]):
                    continue
                
                # Extract repository URL and commit hash
                try:
                    parts = url.split('/commit/')
                    repo_url = parts[0]
                    commit_hash = parts[1].split('#')[0]
                    
                    if not commit_info['repository']:
                        commit_info['repository'] = repo_url
                    
                    if not commit_info['current_commit']:
                        commit_info['current_commit'] = commit_hash
                    elif not commit_info['previous_commit']:
                        commit_info['previous_commit'] = commit_hash
                except Exception as e:
                    Logger.warning(f"Failed to parse commit URL: {url}, Error: {str(e)}")
                    continue
        
        # If we only have current commit, try to get previous commit from GitHub
        if commit_info['repository'] and commit_info['current_commit'] and not commit_info['previous_commit']:
            previous_commit = ErrorHandler.with_retry(
                self.github_api.get_previous_commit,
                commit_info['repository'],
                commit_info['current_commit'],
                error_msg=f"Failed to get previous commit for {commit_info['current_commit']}"
            )
            if previous_commit:
                commit_info['previous_commit'] = previous_commit
        
        # Return None if we don't have all required information
        if not (commit_info['repository'] and commit_info['current_commit'] and commit_info['previous_commit']):
            return None
        
        return commit_info
    
    def _determine_project_type(self, repo_url: str) -> str:
        """
        Determine the type of PHP project based on repository URL.
        
        This method uses the repository URL to infer the project type by checking
        for known project names and patterns.
        """
        repo_name = repo_url.lower().replace('https://github.com/', '')
        
        # Check for known projects in config
        for known_name, project_type in config.known_projects.items():
            if known_name in repo_name:
                return project_type
        
        # Extract owner and repo
        try:
            parts = repo_name.split('/')
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1]
                # Use GitHub API to infer project type
                project_type = ErrorHandler.with_retry(
                    self.github_api.infer_project_type,
                    owner,
                    repo,
                    error_msg=f"Failed to infer project type for {owner}/{repo}"
                )
                if project_type:
                    return project_type
        except Exception as e:
            Logger.warning(f"Failed to determine project type: {str(e)}")
        
        # Default to Library if we can't determine
        return "Library"

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