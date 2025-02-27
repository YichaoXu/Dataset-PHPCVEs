import typer
import shutil
from src.utils.logger import Logger
from src.utils.file_utils import ensure_dir
from src.config import config

def clean(
    cache_type: str = typer.Argument(
        "all", 
        help="Type of cache to clean: 'all', 'collect', 'download', 'statistic', 'cve', or 'processed'"
    )
):
    """
    Clean cache files to free up disk space or force re-processing.
    
    Options:
        all: Clean all cache files
        collect: Clean all collect command cache
        download: Clean all download command cache
        statistic: Clean all statistic command cache
        cve: Clean only raw CVE data
        processed: Clean only processed CVE cache
    """
    # Define cache directories
    inter_dir = config.inter_dir
    collect_dir = config.inter_dir / "collect"
    download_dir = config.inter_dir / "download"
    statistic_dir = config.inter_dir / "statistic"
    cve_dir = collect_dir / "cves"
    processed_dir = collect_dir / "processed"
    
    # Clean all cache
    if cache_type == "all":
        Logger.info(f"Cleaning all cache at {inter_dir}")
        try:
            if inter_dir.exists():
                shutil.rmtree(inter_dir)
                ensure_dir(inter_dir)  # Recreate the directory
                Logger.success("All cache cleaned successfully")
            else:
                Logger.info("No cache to clean")
        except Exception as e:
            Logger.error(f"Failed to clean all cache: {str(e)}")
        return
    
    # Clean command-specific cache
    if cache_type == "collect":
        Logger.info(f"Cleaning collect command cache at {collect_dir}")
        try:
            if collect_dir.exists():
                shutil.rmtree(collect_dir)
                ensure_dir(collect_dir)  # Recreate the directory
                Logger.success("Collect command cache cleaned successfully")
            else:
                Logger.info("No collect command cache to clean")
        except Exception as e:
            Logger.error(f"Failed to clean collect command cache: {str(e)}")
        return
    
    if cache_type == "download":
        Logger.info(f"Cleaning download command cache at {download_dir}")
        try:
            if download_dir.exists():
                shutil.rmtree(download_dir)
                ensure_dir(download_dir)  # Recreate the directory
                Logger.success("Download command cache cleaned successfully")
            else:
                Logger.info("No download command cache to clean")
        except Exception as e:
            Logger.error(f"Failed to clean download command cache: {str(e)}")
        return
    
    if cache_type == "statistic":
        Logger.info(f"Cleaning statistic command cache at {statistic_dir}")
        try:
            if statistic_dir.exists():
                shutil.rmtree(statistic_dir)
                ensure_dir(statistic_dir)  # Recreate the directory
                Logger.success("Statistic command cache cleaned successfully")
            else:
                Logger.info("No statistic command cache to clean")
        except Exception as e:
            Logger.error(f"Failed to clean statistic command cache: {str(e)}")
        return
    
    # Clean specific cache types
    if cache_type == "cve" and cve_dir.exists():
        Logger.info(f"Cleaning CVE data cache at {cve_dir}")
        try:
            shutil.rmtree(cve_dir)
            ensure_dir(cve_dir)  # Recreate the directory
            Logger.success("CVE data cache cleaned successfully")
        except Exception as e:
            Logger.error(f"Failed to clean CVE data cache: {str(e)}")
    
    if cache_type == "processed" and processed_dir.exists():
        Logger.info(f"Cleaning processed CVE cache at {processed_dir}")
        try:
            shutil.rmtree(processed_dir)
            ensure_dir(processed_dir)  # Recreate the directory
            Logger.success("Processed CVE cache cleaned successfully")
        except Exception as e:
            Logger.error(f"Failed to clean processed CVE cache: {str(e)}") 