"""
Core processor module for PHP CVE Dataset Collection Tool.

This module provides functionality to process CVE data, filter for PHP-related
vulnerabilities, and extract GitHub commit information.
"""

import re
import json
import time
import csv
import os
import zipfile
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
    
    def __init__(self, github_api: GitHubAPI, cache_dir: Path, use_cache: bool = True, verify_previous_commit: bool = False):
        """
        Initialize the processor.
        
        Args:
            github_api: GitHub API client
            cache_dir: Directory to store processed CVE data
            use_cache: Whether to use cached data
            verify_previous_commit: Whether to verify that previous commits contain PHP files
        """
        self.github_api = github_api
        self.php_keywords = config.php_keywords
        self.error_handler = ErrorHandler()
        self.use_cache = use_cache
        self.cache_dir = cache_dir
        self.verify_previous_commit = verify_previous_commit
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
        
        # If we have a large number of files, warn the user and ask for confirmation
        file_count = len(json_files)
        Logger.info(f"Found {file_count} CVE JSON files to process")
        
        if file_count > 10000:
            Logger.warning(f"Processing a large number of files ({file_count}) may take a long time")
            Logger.info("Continuing with processing...")
        
        # Process files in batches to avoid memory issues
        batch_size = 5000
        num_batches = (file_count + batch_size - 1) // batch_size
        
        total_successful = 0  # Track total successful extractions
        
        for batch_num in range(num_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, file_count)
            batch_files = json_files[start_idx:end_idx]
            
            Logger.info(f"Processing batch {batch_num+1}/{num_batches} ({len(batch_files)} files)")
            
            # Process this batch
            batch_records = self._process_file_batch(batch_files)
            records.extend(batch_records)
            
            # Update total successful count
            total_successful += len(batch_records)
            
            # Report progress
            processed_so_far = end_idx
            remaining = file_count - processed_so_far
            Logger.info(f"Processed {processed_so_far}/{file_count} files, {remaining} remaining")
        
        # Final summary
        Logger.success(f"Processing complete. Total records extracted: {total_successful} out of {file_count} files")
        
        return records
    
    def _process_file_batch(self, json_files: List[Path]) -> List[CVERecord]:
        """Process a batch of CVE JSON files."""
        batch_records = []
        
        # Create cache directory for processed CVEs
        cache_dir = self.cache_dir
        ensure_dir(cache_dir)
        
        # Count cache hits and misses for reporting
        cache_hits = 0
        cache_misses = 0
        skipped_records = 0
        successful_records = 0  # Track successful extractions
        
        # Track reasons for skipping
        skip_reasons = {
            "not_php": 0,
            "no_cwe": 0,
            "commit_missed": 0,
            "other": 0
        }
        
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
                            
                            # Check if this is a skipped record
                            if cached_data.get("_skipped"):
                                skipped_records += 1
                                # Update skip reason counter
                                reason = cached_data.get("reason", "other")
                                if reason == "Not PHP-related":
                                    skip_reasons["not_php"] += 1
                                elif reason == "Missing or invalid CWE-ID":
                                    skip_reasons["no_cwe"] += 1
                                elif reason == "Missing repository or commit information" or reason == "commit_missed":
                                    skip_reasons["commit_missed"] += 1
                                else:
                                    skip_reasons["other"] += 1
                                
                                ui.update(
                                    advance=1,
                                    description=f"Processing CVEs ({i+1}/{len(json_files)}) - Skipped: {skipped_records}"
                                )
                                continue
                            
                            # Regular cached record
                            record = CVERecord.from_dict(cached_data)
                            batch_records.append(record)
                            cache_hits += 1
                            successful_records += 1  # Count successful extraction
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
                    record_dict = self.process_cve(data, log_callback=ui.log_error)
                    
                    if record_dict:
                        # Valid record - save to cache and add to results
                        try:
                            with open(cache_file, 'w', encoding='utf-8') as f:
                                json.dump(record_dict, f, indent=2)
                        except Exception as e:
                            ui.log_error(f"Cache write error for {cve_id}: {str(e)}")
                        
                        record = CVERecord.from_dict(record_dict)
                        batch_records.append(record)
                        successful_records += 1  # Count successful extraction
                    else:
                        # Skipped record - save reason to cache
                        skipped_record = {
                            "_skipped": True,
                            "cve_id": cve_id,
                            "reason": "Failed validation checks",
                            "timestamp": time.time()
                        }
                        
                        # Try to determine more specific reason
                        if not self._is_php_related(data):
                            skipped_record["reason"] = "Not PHP-related"
                            skip_reasons["not_php"] += 1
                        elif self._extract_cwe_type(data, cve_id) is None:
                            skipped_record["reason"] = "Missing or invalid CWE-ID"
                            skip_reasons["no_cwe"] += 1
                        elif self._extract_repo_info(data, cve_id) is None:
                            # Simplified: just use commit_missed
                            skipped_record["reason"] = "commit_missed"
                            skip_reasons["commit_missed"] += 1
                        else:
                            skip_reasons["other"] += 1
                        
                        # Save skipped record to cache
                        try:
                            with open(cache_file, 'w', encoding='utf-8') as f:
                                json.dump(skipped_record, f, indent=2)
                        except Exception as e:
                            ui.log_error(f"Cache write error for skipped record {cve_id}: {str(e)}")
                        
                        skipped_records += 1
                except Exception as e:
                    error_msg = f"Processing error ({cve_id}): {str(e)}"
                    ui.log_error(error_msg)
                    skip_reasons["other"] += 1
                
                # Update progress
                ui.update(
                    advance=1, 
                    description=f"Processing CVEs ({i+1}/{len(json_files)}) - Cache hits: {cache_hits}, Skipped: {skipped_records}"
                )
            
            # Write log to file if there are errors
            if ui.log_buffer:
                ui.write_log_to_file(str(cache_dir.parent / f"processing_errors_batch.log"))
        
        # Report cache statistics for this batch
        total = cache_hits + cache_misses
        hit_rate = (cache_hits / total) * 100 if total > 0 else 0
        Logger.info(f"Batch statistics: {cache_hits} hits, {cache_misses} misses, {skipped_records} skipped ({hit_rate:.1f}% hit rate)")
        
        # Report skip reasons and successful extractions
        Logger.info(f"Skip reasons: Not PHP: {skip_reasons['not_php']}, No CWE: {skip_reasons['no_cwe']}, "
                   f"Commit missed: {skip_reasons['commit_missed']}, Other: {skip_reasons['other']}")
        Logger.info(f"Successfully extracted: {successful_records} records")
        
        return batch_records
    
    def process_cve(self, data: Dict[str, Any], log_callback=None) -> Optional[Dict[str, Any]]:
        """
        Process a single CVE record to extract PHP-related vulnerability.
        
        Args:
            data: The CVE data to process
            log_callback: Optional callback function to log errors in real-time
        
        Returns:
            Dictionary with CVE information or None if not relevant
        """
        try:
            # Extract CVE ID
            cve_id = self._extract_cve_id(data)
            if not cve_id:
                if log_callback:
                    log_callback("Missing CVE ID")
                return None
            
            # Step 1: Check if PHP-related based on CVE description and metadata
            if not self._is_php_related(data):
                if log_callback:
                    log_callback(f"{cve_id} is not PHP-related based on description")
                return None
            
            # Extract CWE type (can be null)
            cwe_type = self._extract_cwe_type(data, cve_id, log_callback)
            
            # Step 2: Extract GitHub repository and commit information
            # This will check if the commit contains PHP files based on extensions
            repo_info = self._extract_repo_info(data, cve_id, log_callback)
            if not repo_info:
                if log_callback:
                    log_callback(f"{cve_id} has no valid PHP-related commits")
                return None
            
            # Determine project type
            project_type = self._determine_project_type(repo_info['repository'], cve_id, log_callback)
            
            # Create record
            record = {
                'cve_id': cve_id,
                'cwe_type': cwe_type,  # Can be null
                'repository': repo_info['repository'],
                'current_commit': repo_info['current_commit'],
                'previous_commit': repo_info['previous_commit'],
                'project_type': project_type
            }
            
            return record
        except Exception as e:
            if log_callback:
                log_callback(f"Error processing CVE: {str(e)}")
            return None
    
    def save_dataset(self, records: List[CVERecord], dataset_path: Path, cache_path: Path) -> bool:
        """
        Save the dataset to CSV and JSON files.
        
        Args:
            records: List of CVE records
            dataset_path: Path to save the CSV dataset
            cache_path: Path to save the JSON dataset
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Filter out records with any null values for CSV
            csv_records = []
            for record in records:
                # Check if any attribute is None
                if (record.cve_id is None or 
                    record.cwe_type is None or 
                    record.repository is None or 
                    record.current_commit is None or 
                    record.previous_commit is None or 
                    record.project_type is None):
                    continue
                csv_records.append(record)
            
            # Save CSV (only complete records)
            with open(dataset_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['CVE ID', 'CWE Type', 'Repository', 'Current Commit', 'Previous Commit', 'Project Type'])
                
                for record in csv_records:
                    writer.writerow([
                        record.cve_id,
                        record.cwe_type,
                        record.repository,
                        record.current_commit,
                        record.previous_commit,
                        record.project_type
                    ])
            
            # Save JSON (including records with null values)
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump([record.to_dict() for record in records], f, indent=2)
            
            # Log statistics
            total_records = len(records)
            filtered_records = len(csv_records)
            skipped_records = total_records - filtered_records
            
            Logger.info(f"Dataset saved with {total_records} records total")
            if skipped_records > 0:
                Logger.info(f"Note: {skipped_records} records with null values were excluded from CSV but kept in JSON")
                
                # Count records by missing field
                missing_cwe = sum(1 for r in records if r.cwe_type is None)
                missing_repo = sum(1 for r in records if r.repository is None)
                missing_current = sum(1 for r in records if r.current_commit is None)
                missing_previous = sum(1 for r in records if r.previous_commit is None)
                missing_project = sum(1 for r in records if r.project_type is None)
                
                Logger.info(f"Records with missing fields: CWE={missing_cwe}, Repo={missing_repo}, "
                           f"Current commit={missing_current}, Previous commit={missing_previous}, "
                           f"Project type={missing_project}")
            
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
        Check if a CVE is PHP-related based on its description and other metadata.
        
        Args:
            data: CVE data dictionary
            
        Returns:
            True if the CVE is PHP-related, False otherwise
        """
        # Get all text fields that might contain PHP-related information
        text_fields = []
        
        # Check CVE description
        descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
        for desc in descriptions:
            if 'value' in desc:
                text_fields.append(desc['value'])
        
        # Check affected products
        affected = data.get('containers', {}).get('cna', {}).get('affected', [])
        for item in affected:
            if 'product' in item:
                text_fields.append(item['product'])
            if 'vendor' in item:
                text_fields.append(item['vendor'])
        
        # Check references
        references = data.get('containers', {}).get('cna', {}).get('references', [])
        for ref in references:
            if 'url' in ref:
                text_fields.append(ref['url'])
            if 'tags' in ref:
                text_fields.extend(ref['tags'])
        
        # Combine all text fields and convert to lowercase for case-insensitive comparison
        all_text = ' '.join(text_fields).lower()
        
        # Check for PHP-related keywords (all lowercase for comparison)
        php_keywords = [keyword.lower() for keyword in (self.php_keywords + [
            'php', 'wordpress', 'drupal', 'laravel', 'symfony', 'magento', 'codeigniter',
            'joomla', 'typo3', 'prestashop', 'phpbb', 'mediawiki', 'moodle', 'nextcloud',
            'owncloud', 'phpmyadmin', 'phpmailer', 'cakephp', 'zend', 'yii', 'slim',
            'composer', 'packagist', 'pear', 'pecl'
        ])]
        
        # Count how many PHP keywords are in the text (case-insensitive)
        keyword_count = sum(1 for keyword in php_keywords if keyword in all_text)
        
        # If we have multiple PHP keywords, it's likely PHP-related
        return keyword_count >= 2  # Require at least 2 keywords to reduce false positives
    
    def _extract_cwe_type(self, data: Dict, cve_id: str, log_callback=None) -> Optional[str]:
        """Extract CWE type with detailed logging."""
        try:
            # Method 1: Extract from problemtype
            problem_types = data.get('containers', {}).get('cna', {}).get('problemtype', {}).get('descriptions', [])
            
            for problem in problem_types:
                cwe_id = problem.get('cweId')
                if cwe_id and cwe_id.startswith('CWE-'):
                    return cwe_id
            
            # Method 2: Look in the description text
            descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
            for desc in descriptions:
                desc_text = desc.get('value', '')
                
                # Use regex to find CWE pattern in description
                import re
                cwe_matches = re.findall(r'CWE-\d+', desc_text)
                if cwe_matches:
                    return cwe_matches[0]  # Return the first match
            
            # Method 3: Search the entire data structure using regex
            import json
            data_str = json.dumps(data)
            cwe_pattern = r'CWE-\d+'
            matches = re.findall(cwe_pattern, data_str)
            
            if matches:
                return matches[0]  # Return the first match
            
            # If we get here, no CWE ID was found
            if log_callback:
                log_callback(f"No CWE ID found for {cve_id}")
            
            return None
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
            
            # Skip invalid or incomplete URLs
            if not url or len(url) < 10:  # Minimum valid URL length
                continue
            
            # Validate URL format before processing
            if not url.startswith(('http://', 'https://')):
                if log_callback:
                    log_callback(f"Skipping invalid URL format: {url}")
                continue
            
            # Skip non-GitHub URLs
            if 'github.com' not in url:
                continue
            
            if '/commit/' in url:
                # Skip non-commit URLs
                if any(skip in url for skip in ["/compare/", "/issues/", "/pull/", "/tree/"]):
                    continue
                
                # Extract repository URL and commit hash
                try:
                    parts = url.split('/commit/')
                    repo_url = parts[0]
                    
                    # Validate repository URL
                    if not repo_url.startswith(('http://', 'https://')) or 'github.com' not in repo_url:
                        if log_callback:
                            log_callback(f"Invalid repository URL: {repo_url}")
                        continue
                    
                    # Extract commit hash
                    if len(parts) < 2 or not parts[1]:
                        if log_callback:
                            log_callback(f"Missing commit hash in URL: {url}")
                        continue
                    
                    commit_hash = parts[1].split('#')[0]
                    
                    # Validate commit hash format (should be a hex string)
                    if not re.match(r'^[0-9a-f]{7,40}$', commit_hash, re.IGNORECASE):
                        if log_callback:
                            log_callback(f"Invalid commit hash format: {commit_hash}")
                        continue
                    
                    # Extract owner and repo name
                    repo_parts = repo_url.replace('https://github.com/', '').replace('http://github.com/', '').split('/')
                    if len(repo_parts) < 2:
                        if log_callback:
                            log_callback(f"Invalid repository path: {repo_url}")
                        continue
                    
                    owner, repo = repo_parts[0], repo_parts[1]
                    
                    # Skip empty owner or repo
                    if not owner or not repo:
                        if log_callback:
                            log_callback(f"Empty owner or repo in URL: {repo_url}")
                        continue
                    
                    # Get commit details in a single API call
                    commit_details = self.github_api.get_commit_details(owner, repo, commit_hash)
                    
                    if commit_details:
                        # Check if the commit contains PHP files
                        files = commit_details.get("files", [])
                        php_files = [f for f in files if self._is_php_file(f.get("filename", ""))]
                        
                        # If no PHP files found by extension, check file contents
                        if not php_files:
                            for file in files:
                                if "patch" in file and self._check_file_content_for_php(file["patch"]):
                                    php_files.append(file)
                                    break
                        
                        # Check commit message for PHP keywords
                        commit_message = commit_details.get("commit", {}).get("message", "").lower()
                        is_php_related_commit = any(keyword.lower() in commit_message for keyword in self.php_keywords)
                        
                        if not php_files and not is_php_related_commit:
                            if log_callback:
                                log_callback(f"Commit {commit_hash} does not contain PHP files or PHP-related keywords")
                            continue
                        
                        # Get previous commit from parents
                        parents = commit_details.get("parents", [])
                        previous_commit = parents[0]["sha"] if parents else None
                        
                        if log_callback:
                            if php_files:
                                log_callback(f"Found {len(php_files)} PHP files in commit {commit_hash}")
                            if is_php_related_commit:
                                log_callback(f"Commit message contains PHP keywords: {commit_message[:100]}")
                            if previous_commit:
                                log_callback(f"Found parent commit: {previous_commit}")
                        
                        # Store commit info
                        if not commit_info['repository']:
                            commit_info['repository'] = repo_url
                        
                        if not commit_info['current_commit']:
                            commit_info['current_commit'] = commit_hash
                            
                            # Also store previous commit if available
                            if previous_commit and not commit_info['previous_commit']:
                                # Check if we need to verify the previous commit contains PHP files
                                if self.verify_previous_commit:
                                    prev_commit_details = self.github_api.get_commit_details(owner, repo, previous_commit)
                                    if prev_commit_details:
                                        prev_files = prev_commit_details.get("files", [])
                                        prev_php_files = [f for f in prev_files if self._is_php_file(f.get("filename", ""))]
                                        
                                        if prev_php_files:
                                            commit_info['previous_commit'] = previous_commit
                                        elif log_callback:
                                            log_callback(f"Previous commit {previous_commit} does not contain PHP files")
                                    else:
                                        # If we can't get details, use it anyway
                                        commit_info['previous_commit'] = previous_commit
                                else:
                                    # Skip verification and use the previous commit directly
                                    commit_info['previous_commit'] = previous_commit
                        elif not commit_info['previous_commit']:
                            commit_info['previous_commit'] = commit_hash
                    else:
                        if log_callback:
                            log_callback(f"Could not get commit details for {owner}/{repo}/{commit_hash}")
                
                except Exception as e:
                    if log_callback:
                        log_callback(f"URL parse error ({url}): {str(e)}")
                    continue
        
        # If we have repository and current commit but no previous commit, try one more time
        if commit_info['repository'] and commit_info['current_commit'] and not commit_info['previous_commit']:
            try:
                repo_name = commit_info['repository'].replace('https://github.com/', '')
                repo_parts = repo_name.split('/')
                if len(repo_parts) >= 2:
                    owner, repo = repo_parts[0], repo_parts[1]
                    
                    # Get commit details to find parent
                    commit_details = ErrorHandler.with_retry(
                        lambda: self.github_api.get_commit_details(owner, repo, commit_info['current_commit']),
                        error_msg=f"GitHub API error ({repo_name}/{commit_info['current_commit']})"
                    )
                    
                    if commit_details and "parents" in commit_details and commit_details["parents"]:
                        previous_commit = commit_details["parents"][0]["sha"]
                        commit_info['previous_commit'] = previous_commit
                        
                        if log_callback:
                            log_callback(f"Found parent commit: {previous_commit}")
                    elif log_callback:
                        log_callback(f"Could not find parent commit for {repo_name}/{commit_info['current_commit']}")
            except Exception as e:
                if log_callback:
                    log_callback(f"API error for {cve_id}: {str(e)}")
        
        # Return None if we don't have all required information
        if not (commit_info['repository'] and commit_info['current_commit'] and commit_info['previous_commit']):
            return None
        
        return commit_info
    
    def _is_php_file(self, filename: str) -> bool:
        """Check if a file is PHP-related based on its extension."""
        if not filename:
            return False
        
        # Convert filename to lowercase for case-insensitive comparison
        filename_lower = filename.lower()
        
        # Check file extension
        php_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phps', '.inc']
        
        # Also consider HTML files that might contain PHP
        html_extensions = ['.html', '.htm']
        
        # Direct PHP files (case-insensitive)
        if any(filename_lower.endswith(ext) for ext in php_extensions):
            return True
        
        # HTML files with PHP-related names (case-insensitive)
        if any(filename_lower.endswith(ext) for ext in html_extensions):
            php_indicators = ['php', 'wordpress', 'drupal', 'laravel', 'symfony']
            if any(indicator in filename_lower for indicator in php_indicators):
                return True
        
        return False
    
    def _check_file_content_for_php(self, file_content: str) -> bool:
        """Check if file content contains PHP code or PHP-related keywords."""
        if not file_content:
            return False
        
        # Convert file content to lowercase for case-insensitive comparison
        file_content_lower = file_content.lower()
        
        # Check for PHP opening tags (case-insensitive)
        if '<?php' in file_content_lower or '<?' in file_content_lower:
            return True
        
        # Check for PHP-related keywords (all lowercase for comparison)
        php_keywords = [keyword.lower() for keyword in [
            'php', 'wordpress', 'drupal', 'laravel', 'symfony', 'magento', 'codeigniter',
            'function', 'class', 'namespace', 'use', 'require', 'include', 'echo', 'print',
            '$_GET', '$_POST', '$_REQUEST', '$_SERVER', '$_SESSION', '$_COOKIE'
        ]]
        
        # Count how many PHP keywords are in the content (case-insensitive)
        keyword_count = sum(1 for keyword in php_keywords if keyword in file_content_lower)
        
        # If we have multiple PHP keywords, it's likely PHP-related
        return keyword_count >= 3  # Require at least 3 keywords to reduce false positives
    
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

    def _extract_cve_id(self, data: Dict[str, Any]) -> Optional[str]:
        """
        Extract CVE ID from data using multiple methods.
        
        Args:
            data: CVE data dictionary
            
        Returns:
            CVE ID string or None if not found
        """
        # Method 1: Direct extraction from metadata
        cve_id = data.get('cveMetadata', {}).get('cveId')
        if cve_id:
            return cve_id
        
        # Method 2: Look in the data structure
        containers = data.get('containers', {})
        for container_type, container in containers.items():
            if 'cveId' in container:
                return container['cveId']
        
        # Method 3: Use regex to find CVE ID pattern in the entire data
        import re
        import json
        
        # Convert data to string for regex search
        data_str = json.dumps(data)
        
        # Look for CVE ID pattern (CVE-YYYY-NNNNN...)
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        matches = re.findall(cve_pattern, data_str)
        
        if matches:
            return matches[0]  # Return the first match
        
        return None 

    def _check_repo_availability(self, data: Dict[str, Any], cve_id: str) -> str:
        """
        Check if repository information is available and valid.
        
        Args:
            data: CVE data dictionary
            cve_id: CVE ID for logging
            
        Returns:
            Status string: "valid", "invalid_url", "no_repo", "no_commit"
        """
        references = data.get('containers', {}).get('cna', {}).get('references', [])
        
        # Check if there are any references
        if not references:
            return "no_repo"
        
        # Check for GitHub URLs
        github_urls = [ref.get('url', '') for ref in references if 'github.com' in ref.get('url', '')]
        
        if not github_urls:
            return "no_repo"
        
        # Check for valid GitHub URLs
        valid_urls = [url for url in github_urls if url.startswith(('http://', 'https://')) and len(url) > 10]
        
        if not valid_urls:
            return "invalid_url"
        
        # Check for commit URLs
        commit_urls = [url for url in valid_urls if '/commit/' in url]
        
        if not commit_urls:
            return "no_commit"
        
        # If we got here, there are valid GitHub commit URLs
        return "valid" 

    def process_year(self, year: int, force: bool = False) -> List[Dict[str, Any]]:
        """
        Process CVEs for a specific year.
        
        Args:
            year: Year to process
            force: Force reprocessing of cached data
            
        Returns:
            List of processed CVE records
        """
        year_cache = self.cache_dir / f"year_{year}.json"
        
        # Check cache
        if not force and self.use_cache and year_cache.exists():
            Logger.info(f"Using cached data for year {year}")
            try:
                with open(year_cache, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                Logger.warning(f"Failed to load cache for year {year}: {str(e)}")
        
        # Download and extract CVE data
        cve_data = self._download_cve_data(year)
        if not cve_data:
            Logger.warning(f"No CVE data found for year {year}")
            return []
        
        # Filter for PHP-related vulnerabilities
        php_cves = self._filter_php_cves(cve_data)
        if not php_cves:
            Logger.warning(f"No PHP-related CVEs found for year {year}")
            return []
        
        # Process each CVE
        records = []
        with ProgressUI(len(php_cves), f"Processing CVEs for {year}") as progress:
            for i, cve_data in enumerate(php_cves):
                cve_id = cve_data.get('id', f"Unknown-{i}")
                progress.update(0, cve_id)
                
                try:
                    # Extract basic CVE information
                    record = self._extract_cve_info(cve_data)
                    
                    # Extract GitHub commit information
                    if self._extract_github_info(record, cve_data):
                        # Verify that the commit contains PHP files
                        if self._verify_php_files(record):
                            # Get previous commit
                            self._get_previous_commit(record)
                            
                            # Classify project type based on README
                            self._classify_project_type(record)
                            
                            # Add to records
                            records.append(record)
                            progress.log(f"Processed {cve_id}: {record.get('description', '')[:50]}...")
                        else:
                            progress.log_warning(f"Skipped {cve_id}: No PHP files found in commit")
                    else:
                        progress.log_warning(f"Skipped {cve_id}: No GitHub commit information found")
                except Exception as e:
                    progress.log_error(f"Error processing {cve_id}: {str(e)}")
                
                progress.update(1, cve_id)
        
        # Save to cache
        if self.use_cache:
            try:
                with open(year_cache, 'w', encoding='utf-8') as f:
                    json.dump(records, f, indent=2)
            except Exception as e:
                Logger.warning(f"Failed to save cache for year {year}: {str(e)}")
        
        return records

    def _download_cve_data(self, year: int) -> List[Dict[str, Any]]:
        """
        Download and extract CVE data for a specific year.
        
        Args:
            year: Year to download
            
        Returns:
            List of CVE data dictionaries
        """
        # Create cache directories
        cve_dir = self.cache_dir / "cves"
        ensure_dir(cve_dir)
        
        # Download CVE data
        cve_zip = cve_dir / f"cve_{year}.zip"
        if not cve_zip.exists():
            Logger.info(f"Downloading CVE data for year {year}")
            # Download from NVD or CVE Project
            # ...
        
        # Extract CVE data
        cve_extract_dir = cve_dir / f"extract_{year}"
        ensure_dir(cve_extract_dir)
        
        # Extract first level (zip file)
        with zipfile.ZipFile(cve_zip, 'r') as zip_ref:
            zip_ref.extractall(cve_extract_dir)
        
        # Find and extract second level (if needed)
        for nested_zip in cve_extract_dir.glob("**/*.zip"):
            nested_extract_dir = nested_zip.parent / nested_zip.stem
            ensure_dir(nested_extract_dir)
            with zipfile.ZipFile(nested_zip, 'r') as zip_ref:
                zip_ref.extractall(nested_extract_dir)
        
        # Find and parse CVE JSON files
        cve_data = []
        for json_file in cve_extract_dir.glob(f"**/*{year}*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    cve_data.append(data)
            except Exception as e:
                Logger.warning(f"Failed to parse {json_file}: {str(e)}")
        
        return cve_data

    def _filter_php_cves(self, cve_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter CVEs for PHP-related vulnerabilities.
        
        Args:
            cve_data: List of CVE data dictionaries
            
        Returns:
            List of PHP-related CVE data dictionaries
        """
        php_cves = []
        
        for data in cve_data:
            # Check if CVE contains PHP-related keywords
            description = data.get('description', '').lower()
            if any(keyword in description for keyword in self.php_keywords):
                # Check if CVE has a CWE ID
                if 'cwe' in data and data['cwe']:
                    php_cves.append(data)
        
        return php_cves

    def _verify_php_files(self, record: Dict[str, Any]) -> bool:
        """
        Verify that the commit contains PHP files.
        
        Args:
            record: CVE record
            
        Returns:
            True if the commit contains PHP files, False otherwise
        """
        repo_url = record.get('repository')
        commit_sha = record.get('current_commit')
        
        if not repo_url or not commit_sha:
            return False
        
        # Extract owner and repo from URL
        repo_path = repo_url.replace("https://github.com/", "")
        parts = repo_path.split('/')
        if len(parts) < 2:
            return False
        
        owner, repo = parts[0], parts[1]
        
        # Get commit details
        commit_details = self.github_api.get_commit_details(owner, repo, commit_sha)
        if not commit_details:
            return False
        
        # Check if any files have .php extension
        files = commit_details.get('files', [])
        for file in files:
            filename = file.get('filename', '')
            if filename.endswith('.php'):
                return True
        
        return False

    def _get_previous_commit(self, record: Dict[str, Any]) -> bool:
        """
        Get the previous commit for a CVE.
        
        Args:
            record: CVE record
            
        Returns:
            True if successful, False otherwise
        """
        repo_url = record.get('repository')
        commit_sha = record.get('current_commit')
        
        if not repo_url or not commit_sha:
            return False
        
        # Extract owner and repo from URL
        repo_path = repo_url.replace("https://github.com/", "")
        parts = repo_path.split('/')
        if len(parts) < 2:
            return False
        
        owner, repo = parts[0], parts[1]
        
        # Get commit details
        commit_details = self.github_api.get_commit_details(owner, repo, commit_sha)
        if not commit_details:
            return False
        
        # Get previous commit from parents
        parents = commit_details.get('parents', [])
        if parents:
            record['previous_commit'] = parents[0].get('sha')
            return True
        
        return False

    def _classify_project_type(self, record: Dict[str, Any]) -> bool:
        """
        Classify project type based on README content.
        
        Args:
            record: CVE record
            
        Returns:
            True if successful, False otherwise
        """
        repo_url = record.get('repository')
        
        if not repo_url:
            return False
        
        # Extract owner and repo from URL
        repo_path = repo_url.replace("https://github.com/", "")
        parts = repo_path.split('/')
        if len(parts) < 2:
            return False
        
        owner, repo = parts[0], parts[1]
        
        # Get README content
        readme = self.github_api.get_readme(owner, repo)
        if not readme:
            record['project_type'] = "Unknown"
            return False
        
        # Classify based on keywords and weights
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
            record['project_type'] = "Unknown"
            return False
        
        # If multiple types have the same score, prefer more specific types
        candidates = [t for t, s in type_scores.items() if s == max_score]
        priority = ['PHP-SRC', 'Framework Plugin', 'Framework Theme', 'Web App', 'CLI App', 'Library']
        
        for p in priority:
            if p in candidates:
                record['project_type'] = p
                return True
        
        record['project_type'] = candidates[0]
        return True 