import re
import json
import time
import csv
import os
from pathlib import Path
from collections import Counter
from typing import Dict, Optional, List, Any
from src.utils.logger import Logger
from src.config import config
from src.utils.github import GitHubAPI
from cwe_tree import query as cwe_query
from src.utils.file_utils import ensure_dir
from src.utils.error_handler import ErrorHandler
from src.utils.ui import ProgressUI
from src.models.cve import CVERecord

class CVEProcessor:
    """Processes CVE data to extract PHP-related vulnerabilities."""
    
    def __init__(self, github_api: GitHubAPI, cache_dir: Path, use_cache: bool = True):
        """
        Initialize the processor.
        
        Args:
            github_api: GitHub API client
            cache_dir: Directory to store processed CVE data
            use_cache: Whether to use cached data
        """
        self.github_api = github_api
        self.php_keywords = config.php_keywords
        self.error_handler = ErrorHandler()
        self.use_cache = use_cache
        self.cache_dir = cache_dir
        ensure_dir(self.cache_dir)
    
    def process_cve_files(self, cve_dir: Path) -> List[CVERecord]:
        """Process all CVE JSON files in the directory."""
        records = []
        
        Logger.info(f"Searching for CVE JSON files in {cve_dir}")
        
        # First check if we have a nested directory structure
        subdirs = [d for d in cve_dir.glob("*") if d.is_dir()]
        if subdirs:
            Logger.info(f"Found {len(subdirs)} subdirectories in CVE directory")
            
            # Look for CVE files in each subdirectory
            for subdir in subdirs:
                Logger.info(f"Checking subdirectory: {subdir.name}")
                json_files = list(subdir.glob("**/*.json"))
                if json_files:
                    Logger.info(f"Found {len(json_files)} JSON files in {subdir.name}")
                    break
        
        # Search for CVE JSON files
        json_files = []
        
        # First try to find files that start with CVE-
        for file_path in cve_dir.rglob("*.json"):
            file_name = file_path.name
            if file_name.startswith("CVE-"):
                json_files.append(file_path)
        
        # If no CVE-*.json files found, try to find any JSON files that might contain CVE data
        if not json_files:
            Logger.warning("No CVE-*.json files found, searching for any JSON files")
            all_json = list(cve_dir.rglob("*.json"))
            
            if all_json:
                Logger.info(f"Found {len(all_json)} JSON files")
                
                # Check a sample of files to see if they contain CVE data
                sample_size = min(10, len(all_json))
                for file_path in all_json[:sample_size]:
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read(1000)  # Read just the beginning
                            if "CVE" in content and ("vulnerabilities" in content or "cveMetadata" in content):
                                Logger.info(f"Found potential CVE file: {file_path}")
                                json_files.append(file_path)
                    except Exception as e:
                        Logger.warning(f"Error checking file {file_path}: {str(e)}")
        
        if not json_files:
            Logger.warning(f"No CVE JSON files found in {cve_dir}")
            # List directory structure to help debug
            Logger.info("Directory structure:")
            for root, dirs, files in os.walk(cve_dir):
                rel_path = os.path.relpath(root, cve_dir)
                if rel_path == ".":
                    rel_path = ""
                Logger.info(f"  {rel_path}/: {len(files)} files, {len(dirs)} subdirs")
                if files and rel_path == "":
                    Logger.info(f"  Files in root: {files[:5]}")
            return records
        
        Logger.info(f"Processing {len(json_files)} CVE records")
        
        # Create cache directory for processed CVEs
        cache_dir = self.cache_dir
        ensure_dir(cache_dir)
        
        # Count cache hits and misses for reporting
        cache_hits = 0
        cache_misses = 0
        
        # Process files with progress UI
        with ProgressUI(len(json_files), "Processing CVEs") as ui:
            for i, json_file in enumerate(json_files):
                # Update current file in status
                cve_id = json_file.stem  # Get CVE ID from filename (e.g., CVE-2022-1234)
                ui.update(advance=0, current_item=cve_id)
                
                # Check if cache exists for this CVE and cache is enabled
                cache_file = cache_dir / f"{cve_id}.json"
                if self.use_cache and cache_file.exists():
                    try:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            cached_data = json.load(f)
                            record = CVERecord.from_dict(cached_data)
                            records.append(record)
                            cache_hits += 1
                            ui.update(
                                advance=1,
                                description=f"Processing CVEs ({i+1}/{len(json_files)}) - Cache hits: {cache_hits}"
                            )
                            continue
                    except Exception as e:
                        # If there's an error reading the cache, process the file normally
                        ui.log_error(f"Cache read error for {cve_id}: {str(e)}")
                        cache_misses += 1
                else:
                    cache_misses += 1
                
                try:
                    # Try to read the file with multiple encodings
                    try:
                        content, _ = ErrorHandler.try_multiple_encodings(json_file)
                        data = json.loads(content)
                    except (UnicodeError, json.JSONDecodeError) as e:
                        error_msg = f"File read error ({cve_id}): {str(e)}"
                        ui.log_error(error_msg)
                        ui.update(advance=1)
                        continue
                    
                    # Process the CVE data
                    if record_dict := self.process_cve(data, log_callback=ui.log_error):
                        # Save to cache
                        try:
                            with open(cache_file, 'w', encoding='utf-8') as f:
                                json.dump(record_dict, f, indent=2)
                        except Exception as e:
                            ui.log_error(f"Cache write error for {cve_id}: {str(e)}")
                        
                        record = CVERecord.from_dict(record_dict)
                        records.append(record)
                except Exception as e:
                    error_msg = f"Processing error ({cve_id}): {str(e)}"
                    ui.log_error(error_msg)
                
                # Update progress
                ui.update(
                    advance=1, 
                    description=f"Processing CVEs ({i+1}/{len(json_files)}) - Cache hits: {cache_hits}"
                )
            
            # Write log to file if there are errors
            if ui.log_buffer:
                ui.write_log_to_file(str(cve_dir.parent / "processing_errors.log"))
        
        # Report cache statistics
        total = cache_hits + cache_misses
        hit_rate = (cache_hits / total) * 100 if total > 0 else 0
        Logger.info(f"Cache statistics: {cache_hits} hits, {cache_misses} misses ({hit_rate:.1f}% hit rate)")
        
        return records
    
    def process_cve(self, data: Dict[str, Any], log_callback=None) -> Optional[Dict[str, Any]]:
        """
        Process a single CVE record to extract PHP-related vulnerability.
        
        Args:
            data: The CVE data to process
            log_callback: Optional callback function to log errors in real-time
        
        Returns a dictionary with the following keys:
        - cve_id: The CVE identifier
        - cwe_type: The CWE type
        - repository: The GitHub repository URL
        - current_commit: The commit that fixed the vulnerability
        - previous_commit: The commit before the fix (vulnerable version)
        - project_type: The type of PHP project
        
        Returns None if the CVE is not PHP-related or doesn't have required information.
        """
        # Extract CVE ID for better error messages
        cve_id = data.get('cveMetadata', {}).get('cveId', 'Unknown-CVE')
        
        # Check if this is a PHP-related CVE
        if not self._is_php_related(data):
            return None
        
        # Extract CWE type
        cwe_type = self._extract_cwe_type(data, cve_id, log_callback)
        
        # Extract GitHub repository and commit information
        try:
            repo_info = self._extract_repo_info(data, cve_id, log_callback)
            if not repo_info:
                return None
        except Exception as e:
            if log_callback:
                log_callback(f"Repo info extraction failed for {cve_id}: {str(e)}")
            return None
        
        # Determine project type
        try:
            project_type = self._determine_project_type(repo_info['repository'], cve_id, log_callback)
        except Exception as e:
            if log_callback:
                log_callback(f"Project type detection failed for {cve_id}: {str(e)}")
            project_type = "Library"  # Default fallback
        
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
    
    def _extract_cwe_type(self, data: Dict, cve_id: str, log_callback=None) -> Optional[str]:
        """
        Extract CWE type from CVE data, selecting the deepest/most specific CWE when multiple are present.
        
        Args:
            data: CVE data dictionary
            cve_id: CVE ID for logging
            log_callback: Optional callback for logging
            
        Returns:
            CWE ID string or None if not found
        """
        try:
            # Extract all CWE IDs from the data
            cwe_ids = {desc.get("cweId", "UNKNOWN") for entry in data.get("containers", {}).get("cna", {}).get("problemTypes", [])
                      for desc in entry.get("descriptions", []) if "CWE" in desc.get("type", "").upper()}
            
            # Remove any non-CWE or invalid entries
            cwe_ids = {cwe_id for cwe_id in cwe_ids if cwe_id.startswith("CWE-") and cwe_id != "UNKNOWN"}
            
            if not cwe_ids:
                if log_callback:
                    log_callback(f"No CWE IDs found for {cve_id}")
                return None
            
            # If only one CWE ID, return it
            if len(cwe_ids) == 1:
                return next(iter(cwe_ids))
            
            # Get CWE nodes for all IDs
            cwe_nodes = {cwe_id: cwe_query.get_node(cwe_id) for cwe_id in cwe_ids}
            valid_nodes = {cwe_id: node for cwe_id, node in cwe_nodes.items() if node is not None}
            
            if not valid_nodes:
                if log_callback:
                    log_callback(f"No valid CWE nodes found for {cve_id}")
                return next(iter(cwe_ids))  # Return any CWE ID if no valid nodes
            
            # Find the deepest CWE (with highest layer value)
            id_max_map = {cwe_id: max((l for l in node.layer.values()), default=-1) for cwe_id, node in valid_nodes.items()}
            cwe_id = max(valid_nodes, key=lambda cwe_id: id_max_map[cwe_id])
            
            if log_callback and len(cwe_ids) > 1:
                log_callback(f"Selected {cwe_id} from {cwe_ids} as the deepest CWE for {cve_id}")
            
            return cwe_id
        except Exception as e:
            if log_callback:
                log_callback(f"Error extracting CWE type for {cve_id}: {str(e)}")
            return None
    
    def _extract_repo_info(self, data: Dict[str, Any], cve_id: str, log_callback=None) -> Optional[Dict[str, str]]:
        """Extract GitHub repository and commit information with detailed logging."""
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
                    if log_callback:
                        log_callback(f"URL parse error ({url}): {str(e)}")
                    continue
        
        # If we only have current commit, try to get previous commit from GitHub
        if commit_info['repository'] and commit_info['current_commit'] and not commit_info['previous_commit']:
            try:
                repo_name = commit_info['repository'].replace('https://github.com/', '')
                previous_commit = ErrorHandler.with_retry(
                    self.github_api.get_previous_commit,
                    commit_info['repository'],
                    commit_info['current_commit'],
                    error_msg=f"GitHub API error ({repo_name}/{commit_info['current_commit']})"
                )
                if previous_commit:
                    commit_info['previous_commit'] = previous_commit
                elif log_callback:
                    log_callback(f"Could not get previous commit for {repo_name}/{commit_info['current_commit']}")
            except Exception as e:
                if log_callback:
                    log_callback(f"API error for {cve_id}: {str(e)}")
        
        # Return None if we don't have all required information
        if not (commit_info['repository'] and commit_info['current_commit'] and commit_info['previous_commit']):
            return None
        
        return commit_info
    
    def _determine_project_type(self, repo_url: str, cve_id: str, log_callback=None) -> str:
        """Determine project type with detailed logging."""
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
                    error_msg=f"Project type inference failed for {owner}/{repo}"
                )
                if project_type:
                    return project_type
                elif log_callback:
                    log_callback(f"Could not infer project type for {owner}/{repo}")
        except Exception as e:
            if log_callback:
                log_callback(f"Project type error for {cve_id}: {str(e)}")
        
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