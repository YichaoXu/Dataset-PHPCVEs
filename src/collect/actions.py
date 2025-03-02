"""
Implementation of collect command actions
"""

import os
import shutil
from pathlib import Path
from typing import Optional, List

from .downloader import download_cve_data
from .filter import find_php_cves
from .extractor import process_cve_files
from ..logger import logger
from ..config import Config

def collect_cves(
    output_dir: Path,
    use_cache: bool = False,
    github_token: Optional[str] = None,
    ai_classifier: Optional[str] = None,
    verbose: bool = False
) -> None:
    """
    Collect and process PHP-related CVE data.
    
    Args:
        output_dir: Directory where output files will be saved
        use_cache: Whether to use cached data if available
        ai_classifier: Optional AI classifier configuration string
        github_token: GitHub API token for higher rate limits
    """
    # 创建必要目录
    logger.step("Creating necessary directories")
    logger.operation('setup', "Setting up directories",
                    output=str(output_dir),
                    cache=str(Config.DS_CACHE_PATH),
                    inter=str(Config.DS_INTER_PATH))
                    
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir, inter_dir = Config.DS_CACHE_PATH, Config.DS_INTER_PATH
    for dir_path in [inter_dir / 'cve_data', inter_dir / 'responses']:
        os.makedirs(dir_path, exist_ok=True)

    # 检查缓存
    cache_file = cache_dir / 'collected.csv'
    if use_cache and cache_file.exists():
        logger.step("Loading cached results for the previous run")
        logger.operation('cache', "Using cached data", path=str(cache_file))
        return shutil.copy(cache_file, output_dir / 'collected.csv')
    
    # 下载和解压CVE数据
    logger.start_process("Downloading and extracting CVE data")
    cve_data_path = download_cve_data(inter_dir)
    if cve_data_path is None:
        return logger.error("Failed to obtain CVE data")
        
    # 筛选PHP相关的CVE
    logger.start_process("Filtering PHP-related CVEs")
    php_cve_files = list(find_php_cves(cve_data_path))
    if not php_cve_files: 
        return logger.warning("No PHP-related CVEs found")
    logger.success(f"Found {len(php_cve_files)} PHP-related CVEs")
    
    # 处理CVE数据
    logger.start_process("Extracting GitHub repository information")
    output_file = output_dir / 'collected.csv'
    if not process_cve_files(php_cve_files, output_file, github_token, ai_classifier, verbose):
        return logger.error("Failed to process CVE data")
        
    # 缓存结果
    if output_file.exists():
        logger.operation('cache', "Caching results", path=str(cache_file))
        shutil.copy(output_file, cache_file)
    logger.success(f"CVE data processing complete. Results saved to {output_dir}")
    