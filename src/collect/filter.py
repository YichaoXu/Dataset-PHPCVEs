"""
CVE filtering module for PHP-related vulnerabilities.
"""

import json
import time
from pathlib import Path
from typing import List, Dict, Any

from ..config import Config
from ..logger import logger

def _is_php_cve(cve_data: Dict[Any, Any]) -> bool:
    """
    检查CVE是否与PHP相关
    
    检查标准:
    1. 描述中包含PHP关键词
    2. 受影响的产品/配置中包含PHP
    3. 问题类型(CWE)是PHP常见的漏洞类型
    
    Args:
        cve_data: CVE数据字典
        
    Returns:
        bool: 是否是PHP相关的CVE
    """
    try:
        # 获取描述文本
        descriptions = cve_data.get('containers', {}).get('cna', {}).get('descriptions', [])
        desc_text = ' '.join(d.get('value', '').lower() for d in descriptions)
        
        # 获取受影响的产品
        affected = cve_data.get('containers', {}).get('cna', {}).get('affected', [])
        products = ' '.join(a.get('product', '').lower() for a in affected)
        
        # PHP相关的关键词
        php_keywords = {
            'php', 'wordpress', 'drupal', 'laravel', 'symfony', 'composer',
            'phpunit', 'magento', 'cakephp', 'codeigniter', 'zend', 'moodle'
        }
        
        # 检查描述和产品中是否包含PHP相关关键词
        text_to_check = f"{desc_text} {products}"
        return any(keyword in text_to_check for keyword in php_keywords)
        
    except Exception as e:
        logger.debug(f"Error checking PHP relevance: {str(e)}")
        return False

def _save_php_cves_cache(php_cves: List[Path], cache_file: Path) -> None:
    """
    将PHP CVE列表保存到缓存文件
    
    Args:
        php_cves: PHP CVE文件路径列表
        cache_file: 缓存文件路径
    """
    try:
        cache_data = {
            'timestamp': int(time.time()),
            'count': len(php_cves),
            'paths': [str(path) for path in php_cves]
        }
        
        # 确保父目录存在
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        
        # 保存为JSON
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2)
            
        logger.info(f"Saved {len(php_cves)} PHP CVEs to cache: {cache_file}")
                        
    except Exception as e:
        logger.error(f"Failed to save PHP CVEs cache: {str(e)}")

def _load_php_cves_cache(cache_file: Path, max_age: int = 86400) -> List[Path]:
    """
    从缓存文件加载PHP CVE列表
    
    Args:
        cache_file: 缓存文件路径
        max_age: 缓存最大有效期（秒），默认1天
        
    Returns:
        List[Path]: PHP CVE文件路径列表
    """
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
            
        # 检查缓存是否过期
        if int(time.time()) - cache_data['timestamp'] > max_age:
            logger.info("Cache is expired")
            return []
            
        # 检查所有文件是否仍然存在
        php_cves = []
        for path_str in cache_data['paths']:
            path = Path(path_str)
            if not path.exists():
                logger.warning(f"Cached file not found: {path}")
                return []  # 如果有文件丢失，放弃使用缓存
            php_cves.append(path)
            
        if len(php_cves) != cache_data['count']:
            logger.warning("Cache count mismatch")
            return []
            
        logger.info(f"Loaded {len(php_cves)} PHP CVEs from cache: {cache_file}")
        return php_cves
        
    except Exception as e:
        logger.error(f"Failed to load PHP CVEs cache: {str(e)}")
        return []

def find_php_cves(cve_dir: Path) -> List[Path]:
    """
    在CVE目录中查找PHP相关的CVE文件
    
    Args:
        cve_dir: CVE文件目录路径
        
    Returns:
        List[Path]: PHP相关的CVE文件路径列表
    """
    # 检查缓存
    cache_file = Config.DS_INTER_PATH / 'php_cves.json'
    if cache_file.exists():
        logger.info("Found existing PHP CVEs cache")
        cached_cves = _load_php_cves_cache(cache_file)
        if cached_cves:  # 如果成功加载缓存
            return cached_cves
            
    logger.info(f"Searching for PHP CVEs in: {cve_dir}")
    total_files = 0
    php_cves = []
    
    try:
        # 递归遍历所有json文件
        for json_file in cve_dir.rglob('*.json'):
            total_files += 1
            
            if total_files % 1000 == 0:
                logger.info(f"Processed {total_files} files, found {len(php_cves)} PHP CVEs")
            
            try:
                # 读取并解析JSON文件
                with open(json_file, 'r', encoding='utf-8') as f:
                    cve_data = json.load(f)
                
                # 检查是否是PHP相关的CVE
                if _is_php_cve(cve_data):
                    logger.debug(f"Found PHP CVE: {json_file.name}")
                    php_cves.append(json_file)
                    
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON file {json_file}: {str(e)}")
                continue
            except Exception as e:
                logger.warning(f"Error processing {json_file}: {str(e)}")
                continue
                
    except Exception as e:
        logger.error(f"Error scanning directory {cve_dir}: {str(e)}")
        
    finally:
        logger.info(f"Scan complete: found {len(php_cves)} PHP CVEs in {total_files} total files")
        
        # 保存缓存
        if php_cves:
            _save_php_cves_cache(php_cves, cache_file)
            
        return php_cves 