"""
CVE数据下载和解压处理模块
"""

import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

from src.config import Config
from src.logger import logger

def _download_file(url: str, target_path: Path) -> bool:
    """
    下载文件到指定路径
    
    Args:
        url: 下载源URL
        target_path: 保存目标路径
        
    Returns:
        bool: 下载是否成功
    """
    try:
        logger.operation('download', 'Starting download', 
                       path=str(target_path),
                       url=url)
        
        urllib.request.urlretrieve(url, target_path)
        logger.success("Download completed successfully")
        return True
    except Exception as e:
        logger.error(f"Download failed: {str(e)}")
        if target_path.exists():
            logger.operation('clean', "Cleaning up failed download file", 
                           path=str(target_path))
            target_path.unlink()
        return False

def _extract_zip(zip_path: Path, extract_path: Path, inner_zip_path: Optional[Path] = None) -> bool:
    """
    解压ZIP文件
    
    Args:
        zip_path: ZIP文件路径
        extract_path: 解压目标路径
        inner_zip_path: 内层zip文件的保存路径（用于处理嵌套zip）
        
    Returns:
        bool: 解压是否成功
    """
    logger.operation('extract', "Starting file extraction",
                    path=str(zip_path),
                    target=str(extract_path))
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            if inner_zip_path:
                logger.step("Extracting nested cves.zip file")
                with zip_ref.open('cves.zip') as nested_zip:
                    with open(inner_zip_path, 'wb') as f:
                        f.write(nested_zip.read())
                logger.success("Inner zip extraction completed")
            else:
                logger.step("Extracting all files")
                zip_ref.extractall(extract_path)
                logger.success("Extraction completed")
        return True
    except Exception as e:
        logger.error(f"Extraction failed: {str(e)}")
        return False

def download_cve_data(cache_dir: Path) -> Optional[Path]:
    """
    下载并解压CVE数据
    
    Args:
        cache_dir: 缓存目录路径
        
    Returns:
        Optional[Path]: 解压后的CVE数据目录路径，失败时返回None
    """
    try:
        logger.start_process("CVE data download and extraction process")
        
        # 准备路径
        cve_data_dir = cache_dir / 'cve_data'
        cve_zip_path = cve_data_dir / 'cves.zip'
        inner_zip_path = cve_data_dir / 'inner_cves.zip'
        extract_path = cve_data_dir / 'extracted'
        
        logger.step("Initializing paths")
        logger.operation('cache', "Setting up directories",
                       cache_dir=str(cache_dir),
                       cve_data=str(cve_data_dir),
                       zip_file=str(cve_zip_path),
                       extract=str(extract_path))
        
        # 创建必要的目录
        cve_data_dir.mkdir(parents=True, exist_ok=True)
        extract_path.mkdir(parents=True, exist_ok=True)
        
        # 检查是否需要下载
        if not cve_zip_path.exists():
            logger.step("No existing CVE data file found")
            if not _download_file(Config.CVELISTV5_URL, cve_zip_path):
                logger.error("Download process failed")
                return None
        else:
            logger.operation('cache', "Using existing CVE data file", 
                           path=str(cve_zip_path))
        
        # 检查是否已经解压
        if not any(extract_path.iterdir()):
            logger.step("Starting extraction process")
            
            # 解压外层zip
            logger.step("Step 1: Extracting outer zip file")
            if not _extract_zip(cve_zip_path, extract_path, inner_zip_path):
                logger.error("Failed to extract outer zip file")
                return None
            
            # 解压内层zip
            logger.step("Step 2: Extracting inner zip file")
            if not _extract_zip(inner_zip_path, extract_path):
                logger.error("Failed to extract inner zip file")
                return None
            
            # 清理中间文件
            if inner_zip_path.exists():
                logger.operation('clean', "Cleaning up temporary file", 
                               path=str(inner_zip_path))
                inner_zip_path.unlink()
                
            logger.success("Extraction process completed successfully")
        else:
            logger.operation('cache', "Using existing extracted data", 
                           path=str(extract_path))
        
        logger.end_process("CVE data preparation completed successfully")
        return extract_path
        
    except Exception as e:
        logger.error(f"Unexpected error during CVE data processing: {str(e)}")
        return None 