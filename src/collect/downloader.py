"""
CVE数据下载和解压处理模块
"""

import urllib.request
import zipfile
from pathlib import Path
from typing import Optional
from rich.progress import (
    Progress, SpinnerColumn, TimeElapsedColumn,
    TextColumn, BarColumn, TaskProgressColumn,
    DownloadColumn, TransferSpeedColumn, Progress
)
from rich.console import Group
from rich.live import Live
import time

from ..config import Config
from ..logger import logger

def _ensure_cache_dirs():
    """确保所有缓存目录存在"""
    Config.DS_CACHE_PATH.mkdir(parents=True, exist_ok=True)
    Config.DS_INTER_PATH.mkdir(parents=True, exist_ok=True)

def _create_download_progress() -> Progress:
    """创建下载进度条"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        "•",
        DownloadColumn(),
        "•",
        TransferSpeedColumn(),
        "•",
        TimeElapsedColumn(),
    )

def _create_extract_progress() -> Progress:
    """创建解压进度条"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        "•",
        TimeElapsedColumn(),
    )

def _download_file(url: str, target_path: Path, progress: Progress) -> bool:
    """
    下载文件到指定路径
    
    Args:
        url: 下载源URL
        target_path: 保存目标路径
        progress: 进度条对象
        
    Returns:
        bool: 下载是否成功
    """
    # 确保缓存目录存在
    _ensure_cache_dirs()
    
    # 下载（如果需要）
    if target_path.exists() and target_path.stat().st_size > 0: 
        logger.operation('cache', "Using existing CVE data file", path=str(target_path))
        return True
        
    try:
        # 创建下载任务
        task_id = progress.add_task(
            "[bold cyan]Downloading CVE data...",
            total=None  # 初始时不知道总大小
        )
        
        # 下载进度回调
        def hook(count: int, block_size: int, total_size: int):
            if progress.tasks[task_id].total != total_size:
                progress.update(task_id, total=total_size)
            progress.update(task_id, advance=block_size)
        
        # 开始下载
        urllib.request.urlretrieve(url, target_path, reporthook=hook)
        return True
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Download failed: {error_msg}")
        if target_path.exists():
            target_path.unlink()
        return False

def _is_extracted(extract_path: Path) -> bool:
    """
    检查目录是否已经解压过
    
    Args:
        extract_path: 解压目标路径
        
    Returns:
        bool: 是否已解压
    """
    marker_file = extract_path / '.extracted'
    if marker_file.exists():
        try:
            with open(marker_file, 'r') as f:
                timestamp = float(f.read().strip())
                # 检查解压标记是否在7天内
                if time.time() - timestamp < 7 * 24 * 3600:
                    return True
        except Exception:
            pass
    return False

def _mark_extracted(extract_path: Path) -> None:
    """
    标记目录为已解压状态
    
    Args:
        extract_path: 解压目标路径
    """
    marker_file = extract_path / '.extracted'
    try:
        with open(marker_file, 'w') as f:
            f.write(str(time.time()))
    except Exception as e:
        logger.warning(f"Failed to create extraction marker: {e}")

def _extract_zip(zip_path: Path, extract_path: Path, progress: Progress, task_id: Optional[int] = None) -> bool:
    """
    递归解压ZIP文件，包括内部的ZIP文件
    
    Args:
        zip_path: ZIP文件路径
        extract_path: 解压目标路径
        progress: 进度条对象
        task_id: 父任务ID（用于子ZIP文件）
        
    Returns:
        bool: 解压是否成功
    """
    try:
        # 确保缓存目录存在
        _ensure_cache_dirs()
        
        # 检查是否已解压
        if _is_extracted(extract_path):
            logger.operation('cache', "Using existing extracted data", path=str(extract_path))
            return True
            
        # 创建解压任务（如果没有父任务）
        if task_id is None:
            task_id = progress.add_task(f"[bold cyan]Extracting {zip_path.name}...",total=None)
            
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # 获取文件总数
            total_files = len(zip_ref.filelist)
            if task_id is not None:
                progress.update(task_id, total=total_files)
            
            # 解压所有文件
            for i, file in enumerate(zip_ref.filelist, 1):
                # 更新进度
                if task_id is not None:
                    progress.update(task_id, 
                                 advance=1,
                                 description=f"[bold cyan]Extracting {zip_path.name}... ({i}/{total_files})")
                
                # 解压当前文件
                zip_ref.extract(file, extract_path)
                
                # 如果是ZIP文件，创建子任务并递归解压
                if file.filename.lower().endswith('.zip'):
                    nested_zip = extract_path / file.filename
                    nested_dir = extract_path / file.filename[:-4]  # 移除.zip后缀
                    nested_dir.mkdir(parents=True, exist_ok=True)
                    
                    # 创建子任务
                    subtask_id = progress.add_task(
                        f"[bold blue]Extracting {file.filename}...",
                        total=None
                    )
                    
                    # 递归解压
                    if nested_zip.exists():
                        success = _extract_zip(nested_zip, nested_dir, progress, subtask_id)
                        if not success:
                            logger.warning(f"Failed to extract nested zip: {file.filename}")
                        
                        # 删除中间ZIP文件
                        try:
                            nested_zip.unlink()
                        except Exception as e:
                            logger.debug(f"Failed to remove intermediate zip {file.filename}: {e}")
                    
                    # 完成子任务
                    progress.update(subtask_id, visible=False)
            
        # 标记为已解压
        _mark_extracted(extract_path)
        return True
        
    except Exception as e:
        logger.error(f"Extraction failed: {str(e)}")
        if task_id is not None:
            progress.update(task_id, description=f"[bold red]Extraction failed: {zip_path.name}")
        return False

def download_cve_data(target_dir: Path) -> Optional[Path]:
    """
    下载并解压CVE数据
    
    Args:
        target_dir: 目标目录路径
        
    Returns:
        Optional[Path]: 解压后的CVE数据目录路径，失败时返回None
    """
    try:
        # 确保缓存目录存在
        _ensure_cache_dirs()
        
        # 准备路径
        cve_data_dir = target_dir / 'cve_data'
        cve_zip_path = cve_data_dir / 'cves.zip'
        extract_path = cve_data_dir / 'extracted'
        
        # 创建必要的目录
        cve_data_dir.mkdir(parents=True, exist_ok=True)
        extract_path.mkdir(parents=True, exist_ok=True)
        
        # 创建进度条
        progress = _create_download_progress()
        with Live(progress, refresh_per_second=10) as live:
            # 下载
            if not _download_file(Config.CVELISTV5_URL, cve_zip_path, progress):
                raise RuntimeError("Failed to download CVE data")
                
            # 切换到解压进度条
            progress = _create_extract_progress()
            live.update(progress)
            
            # 解压（支持嵌套ZIP）
            if not _extract_zip(cve_zip_path, extract_path, progress):
                raise RuntimeError("Failed to extract CVE data")
                
            # 检查是否成功
            if not any(extract_path.glob('**/*.json')):
                raise RuntimeError("No CVE data files found after extraction")
                
        return extract_path
        
    except Exception as e:
        logger.error(f"Unexpected error during CVE data processing: {str(e)}")
        return None 