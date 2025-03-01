"""
Information extraction module for CVE data
"""

import json, csv, re, time, random
import urllib.request
import urllib.error
import hashlib
from pathlib import Path
from cwe_tree import query
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple, Set
from classifier import classify_description_ai, classify_description_heuristic
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from ..logger import logger
from ..config import Config

# GitHub API配置
_HEADERS = {
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'Dataset-PHPCVEs'
}
_GITHUB_CACHE_DIR = Config.DS_INTER_PATH / 'github_responses'
_AI_CLASS_CACHE_DIR = Config.DS_INTER_PATH / 'ai_classifications'  # 新增AI分类缓存目录
_GITHUB_CACHE_DIR.mkdir(parents=True, exist_ok=True)
_AI_CLASS_CACHE_DIR.mkdir(parents=True, exist_ok=True)  # 创建AI分类缓存目录

# ====== 缓存功能 ======

def _load_cache(url: str) -> Optional[Dict]:
    """
    从缓存加载响应数据
    
    Args:
        url: 请求URL        
    Returns:
        Optional[Dict]: 缓存的响应数据
    """
    url_hash = hashlib.md5(url.encode()).hexdigest()
    cache_file = _GITHUB_CACHE_DIR / f"{url_hash}.json"
    if not cache_file.exists():
        return None
        
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
            cache_days = 7 
            if time.time() - cache_data['timestamp'] < cache_days * 24 * 3600:
                logger.debug(f"Cache hit for {url}")
                return cache_data['data']
    except Exception as e:
        logger.debug(f"Error loading cache for {url}: {e}")
    return None

def _save_cache(url: str, data: Dict, cache_type: str = 'github') -> None:
    """
    保存响应数据到缓存
    
    Args:
        url: 请求URL
        data: 响应数据
        cache_type: 缓存类型 ('github' 或 'aicg')
    """
    try:
        url_hash = hashlib.md5(url.encode()).hexdigest()
        cache_file = _GITHUB_CACHE_DIR / f"{url_hash}.json"
        cache_data = {
            'timestamp': time.time(),
            'url': url,
            'data': data
        }
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2)
    except Exception as e:
        logger.debug(f"Error saving cache for {url} ({cache_type}): {e}")

def _handle_rate_limit(response: urllib.error.HTTPError) -> int:
    """处理API速率限制"""
    try:
        headers = dict(response.headers)
        reset_time = headers.get('X-RateLimit-Reset')
        remaining = headers.get('X-RateLimit-Remaining', '0')
        limit = headers.get('X-RateLimit-Limit', '60')
        
        if reset_time:
            current_time = int(time.time())
            wait_time = max(int(reset_time) - current_time + 1, 60)
            
            # 剩余配额不到10%时增加等待时间
            if int(remaining) < int(limit) * 0.1:
                wait_time += 30
                
            logger.warning(f"\nRate limit reached ({remaining}/{limit})")
            logger.warning(f"Waiting {wait_time} seconds until reset...")
            return wait_time
            
    except Exception as e:
        logger.error(f"Error handling rate limit: {e}")
        
    return 3600  # 出错时默认等待1小时

def _make_request(url: str, token: Optional[str] = None, progress: Optional[Progress] = None, task_id: Optional[int] = None) -> Optional[Dict]:
    """发送GitHub API请求"""
    # 设置请求头
    headers = _HEADERS.copy()
    if token:
        headers['Authorization'] = f'Bearer {token}'
        
    # 检查缓存
    cached_data = _load_cache(url)
    if cached_data is not None:
        return cached_data
    # 重试设置
    retry_attempts = 0
    max_retries = 5
    base_delay = 2
    
    # 提取仓库信息用于日志
    repo_info = "unknown"
    if "/repos/" in url:
        parts = url.split("/repos/")[1].split("/")
        if len(parts) >= 2:
            repo_info = f"{parts[0]}/{parts[1]}"
            
    # 发送请求
    while retry_attempts < max_retries:
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request) as response:
                # 记录API配额使用情况
                remaining = response.headers.get('X-RateLimit-Remaining', '0')
                limit = response.headers.get('X-RateLimit-Limit', '60')
                reset_time = response.headers.get('X-RateLimit-Reset', '0')
                reset_datetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(reset_time)))
                logger.info(f"GitHub API Rate Limit: {remaining}/{limit}, Reset at: {reset_datetime}")
                
                data = json.loads(response.read().decode('utf-8'))
                _save_cache(url, data)
                return data
                
        except urllib.error.HTTPError as e:
            if e.code in {403, 429}:  # 速率限制
                wait_time = _handle_rate_limit(e)
                # 更新进度显示
                if progress and task_id is not None:
                    progress.update(task_id, status=f"[yellow]Rate limit reached, waiting {wait_time}s...")
                time.sleep(wait_time)
                continue
                
            elif e.code in {500, 502, 503, 504}:  # 服务器错误
                retry_attempts += 1
                delay = base_delay * (2 ** retry_attempts) + random.uniform(0, 1)
                if progress and task_id is not None:
                    progress.update(task_id, status=f"[yellow]Server error, retrying in {delay:.1f}s...")
                time.sleep(min(delay, 300))
                
            else:  # 其他错误
                if e.code == 404:
                    logger.debug(f"API request failed for {repo_info}: 404 Not Found")
                else:
                    logger.debug(f"API request failed for {repo_info}: {e.code}")
                return None
                
        except Exception as e:
            logger.debug(f"Request error for {repo_info}: {e}")
            retry_attempts += 1
            time.sleep(base_delay * (2 ** retry_attempts))
            
    return None

def _get_commit_info(repo: str, commit_hash: str, token: Optional[str] = None, progress: Optional[Progress] = None, task_id: Optional[int] = None) -> Optional[Dict]:
    """获取提交信息"""
    if not repo or not commit_hash:
        return None
        
    url = f"https://api.github.com/repos/{repo}/commits/{commit_hash}"
    return _make_request(url, token, progress, task_id)

def get_repo_info(repo: str, token: Optional[str] = None) -> Optional[Dict]:
    """
    获取仓库信息
    
    Args:
        repo: 仓库名称 (格式: owner/repo)
        token: GitHub API token
        
    Returns:
        Optional[Dict]: 仓库信息
    """
    if not repo:
        return None
        
    url = f"https://api.github.com/repos/{repo}"
    return _make_request(url, token)

# ====== CVE 提取功能 ======

def _extract_cwe_id(cve_data: Dict) -> Optional[str]:
    """
    提取CWE IDs并找出最高level的CWE
    
    Args:
        cve_data: CVE JSON数据
        
    Returns:
        Optional[str]: 最高level的CWE ID
    """
    cwe_nodes = set()    
    # 获取problemtype_data中的CWE信息
    try:
        problemtype_data = cve_data.get('cve', {}).get('problemtype', {}).get('problemtype_data', [])
        for problem in problemtype_data:
            for desc in problem.get('description', []):
                if desc.get('lang') != 'en': continue
                cwe_value = str(desc.get('value', ''))
                if not cwe_value.startswith('CWE-'): continue
                cwe_node = query.get_node(cwe_value)
                if cwe_node: cwe_nodes.add(cwe_node)
    except Exception as e:
        logger.debug(f"Error extracting CWE IDs from problemtype: {e}")    
    
    # 如果常规方法没有找到CWE IDs，使用正则表达式搜索整个JSON
    if not cwe_nodes:
        json_str = json.dumps(cve_data)
        matches = re.findall(r'CWE-\d{1,4}', json_str)
        cwe_nodes = (query.get_node(cwe_id) for cwe_id in matches)
        cwe_nodes = set(n for n in cwe_nodes if n is not None)
    
    if not cwe_nodes: return None
    max_cwe = max(cwe_nodes, key=lambda n: max(n.layer.values()))
    return max_cwe.cwe_id

def _is_php_file(filename: str) -> bool:
    """检查文件是否为PHP相关文件"""
    if not filename: return False
    filename_lower = filename.lower()
    php_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phps', '.inc']
    html_extensions = ['.html', '.htm']
    
    if any(filename_lower.endswith(ext) for ext in php_extensions): return True
    if any(filename_lower.endswith(ext) for ext in html_extensions):
        php_indicators = ['php', 'wordpress', 'drupal', 'laravel', 'symfony']
        if any(indicator in filename_lower for indicator in php_indicators): return True
    return False

def _determine_project_type(repo: str, aicg_api: Optional[Dict] = None) -> str:
    """
    确定项目类型，使用readme和description进行分类
    
    Args:
        repo: GitHub仓库名称 (格式: owner/repo)
        aicg_api: AI分类器配置，包含必要的API参数
        
    Returns:
        str: 项目类型 (Framework/Plugin/Library/WebApp/Unknown)
    """
    if not repo: return "Unknown"
    
    repo_url = f"https://github.com/{repo}"
    
    def get_highest_probability_type(results: Dict[str, float]) -> Optional[str]:
        """从概率字典中获取最高概率的类型"""
        if not results: return None
        project_type, confidence = max(results.items(), key=lambda x: x[1])
        logger.debug(f"Classification results for {repo}: {results}")
        logger.debug(f"Selected type: {project_type} with confidence: {confidence:.2f}")
        return project_type
    try:
        # 获取仓库信息
        repo_info = get_repo_info(repo)
        if not repo_info:
            logger.debug(f"Failed to get repository info for {repo}")
            return "Unknown"
            
        # 获取description
        description = repo_info.get('description', '')
        
        # 获取readme内容
        readme_url = f"https://raw.githubusercontent.com/{repo}/master/README.md"
        readme_content = ''
        try:
            request = urllib.request.Request(readme_url, headers=_HEADERS)
            with urllib.request.urlopen(request) as response:
                readme_content = response.read().decode('utf-8')[:200]
        except Exception as e:
            # 如果master分支不存在，尝试main分支
            try:
                readme_url = f"https://raw.githubusercontent.com/{repo}/main/README.md"
                request = urllib.request.Request(readme_url, headers=_HEADERS)
                with urllib.request.urlopen(request) as response:
                    readme_content = response.read().decode('utf-8')[:200]
            except Exception as e2:
                logger.debug(f"Error getting readme content for {repo}: {e2}")
        
        # 组合项目描述
        project_desc = f"Repository: {repo_url}; \nDescription: {description}\nReadme: {readme_content}"
        # 使用AI分类器
        if aicg_api:
            # 生成缓存文件名
            cache_key = hashlib.md5(f"{repo}:{aicg_api['model_name']}:{project_desc}".encode()).hexdigest()
            cache_file = _AI_CLASS_CACHE_DIR / f"{cache_key}.json"
            # 检查缓存
            if cache_file.exists():
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)
                        # 缓存30天
                        if time.time() - cache_data['timestamp'] < 30 * 24 * 3600:
                            logger.debug(f"Using cached AI classification for {repo}")
                            return cache_data['project_type']
                except Exception as e:
                    logger.debug(f"Error loading AI classification cache for {repo}: {e}")
            # 调用AI分类
            api_url, model_name, api_key = aicg_api['api_url'], aicg_api['model_name'], aicg_api['api_key']
            results = classify_description_ai(project_desc, "php", api_url, model_name, api_key)
            if results:
                project_type = get_highest_probability_type(results)
                if project_type:
                    logger.debug(f"AI classified {repo} as {project_type}")
                    # 保存到缓存
                    try:
                        cache_data = {
                            'timestamp': time.time(),
                            'repo': repo,
                            'model_name': aicg_api['model_name'],
                            'project_type': project_type,
                            'description': project_desc,
                            'probabilities': results
                        }
                        with open(cache_file, 'w', encoding='utf-8') as f:
                            json.dump(cache_data, f, indent=2)
                    except Exception as e:
                        logger.debug(f"Error saving AI classification cache for {repo}: {e}")
                    return project_type
        # 使用启发式分类
        results = classify_description_heuristic(project_desc, "php")
        if results:
            project_type = get_highest_probability_type(results)
            if project_type:
                return project_type
            
    except Exception as e:
        logger.debug(f"Classification failed for {repo}: {e}")
        
    return "Unknown"

def _normalize_repo_name(repo: Optional[str]) -> Optional[str]:
    """
    验证并规范化仓库名称
    
    Args:
        repo: 仓库名称 (格式: owner/repo)
        
    Returns:
        Optional[str]: 规范化的仓库名称，无效时返回None
    """
    if not repo:
        return None
        
    # 移除可能的URL前缀
    if 'github.com/' in repo:
        repo = repo.split('github.com/')[-1]
    
    # 验证格式
    parts = repo.strip('/').split('/')
    if len(parts) != 2:
        return None
        
    owner, name = parts
    if not owner or not name:
        return None
        
    return f"{owner}/{name}"

def _extract_github_info(reference_data: List[Dict], github_token: Optional[str] = None, cve_data: Optional[Dict] = None):
    """
    从引用数据中提取GitHub信息，如果常规方法失败则使用正则表达式
    
    Args:
        reference_data: 引用数据列表
        github_token: GitHub API token
        cve_data: 完整的CVE数据（用于正则匹配）
        
    Returns:
        Tuple[Optional[str], Optional[str], Optional[str]]: (repo_name, commit_hash, pre_commit)
    """
    repo, patch_hex, pre_hex = None, None, None
    
    # 记录所有引用
    logger.debug(f"Processing {len(reference_data)} references")
    
    def extract_from_url(url: str) -> Tuple[Optional[str], Optional[str]]:
        """从URL中提取仓库和commit信息"""
        try:
            parsed = urlparse(url)
            path_parts = parsed.path.strip('/').split('/')
            logger.debug(f"URL path parts: {path_parts}")
            
            # 检查是否是commit URL
            if len(path_parts) < 4 or path_parts[2] != 'commit':
                return None, None
                
            # 规范化仓库名称
            repo = _normalize_repo_name(f"{path_parts[0]}/{path_parts[1]}")
            if not repo:
                return None, None
                
            return repo, path_parts[3]
            
        except Exception as e:
            logger.debug(f"Error parsing GitHub URL {url}: {e}")
            return None, None
    
    # 1. 首先尝试从reference_data中提取
    for ref in reference_data:
        url = str(ref.get('url', ''))
        logger.debug(f"Checking reference URL: {url}")
        
        if not url or 'github.com' not in url:
            continue
            
        repo, patch_hex = extract_from_url(url)
        if repo and patch_hex:
            logger.debug(f"Found potential commit from reference: {repo}:{patch_hex}")
            break
    
    # 2. 如果常规方法失败，使用正则表达式搜索整个JSON
    if not (repo and patch_hex) and cve_data:
        logger.debug("Regular method failed, trying regex search")
        json_str = json.dumps(cve_data)
        # 匹配GitHub commit URLs
        commit_pattern = r'https?://github\.com/([^/]+/[^/]+)/commit/([a-f0-9]{40})'
        matches = re.finditer(commit_pattern, json_str)
        
        for match in matches:
            potential_repo = _normalize_repo_name(match.group(1))
            potential_commit = match.group(2)
            if potential_repo:
                repo, patch_hex = potential_repo, potential_commit
                logger.debug(f"Found potential commit from regex: {repo}:{patch_hex}")
                break
    
    # 如果找到了repo和commit，验证并获取parent
    if repo and patch_hex:
        # 验证是否包含PHP文件
        commit_data = _get_commit_info(repo, patch_hex, github_token)
        if commit_data:
            # 检查文件类型
            patch_files = list(f.get('filename', '') for f in commit_data.get('files', []))
            logger.debug(f"Files in commit: {patch_files}")
            
            if any(_is_php_file(f) for f in patch_files):
                # 获取parent commit
                parents = commit_data.get('parents', [])
                pre_hex = parents[0].get('sha') if parents else None
                if not pre_hex:
                    logger.debug(f"No parent commit found for {repo}:{patch_hex}")
                else:
                    logger.debug(f"Found parent commit: {pre_hex}")
                    
                logger.debug(f"Successfully extracted GitHub info: {repo}, {patch_hex}, {pre_hex}")
                return repo, patch_hex, pre_hex
            else:
                logger.debug(f"No PHP files found in commit {patch_hex}")
    
    logger.debug("No valid GitHub information found")
    return None, None, None

def _create_progress() -> Progress:
    """创建处理进度显示器"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
        TextColumn("[bold]{task.fields[status]}"),
        expand=True
    )

def _parse_aicg_api(api_str: Optional[str]) -> Optional[Dict]:
    """
    解析AICG API字符串
    
    Args:
        api_str: API配置字符串 (格式: api_url:model_name:api_key)
        
    Returns:
        Optional[Dict]: API配置字典
    """
    if not api_str:
        return None
        
    try:
        parts = api_str.split(':')
        if len(parts) != 3:
            logger.warning(f"Invalid AICG API format: {api_str}")
            return None
            
        api_url, model_name, api_key = parts
        
        # 验证API URL格式
        if not api_url.startswith(('http://', 'https://')):
            api_url = f"https://{api_url}"
            
        return {
            'api_url': api_url,
            'model_name': model_name,
            'api_key': api_key
        }
        
    except Exception as e:
        logger.warning(f"Failed to parse AICG API string: {e}")
        return None

def _validate_github_token(token: Optional[str]) -> bool:
    """
    验证GitHub token是否有效
    
    Args:
        token: GitHub API token
        
    Returns:
        bool: token是否有效
    """
    if not token:
        return False
        
    url = "https://api.github.com/user"
    headers = _HEADERS.copy()
    headers['Authorization'] = f'Bearer {token}'
    
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request) as response:
            return response.status == 200
            
    except urllib.error.HTTPError as e:
        if e.code == 401:  # Unauthorized
            logger.warning("GitHub token is invalid or expired")
        elif e.code == 403:  # Rate limit or permission issue
            logger.warning("GitHub token has insufficient permissions or rate limited")
        else:
            logger.warning(f"GitHub API error: {e.code}")
        return False
        
    except urllib.error.URLError as e:
        logger.warning(f"Network error while validating GitHub token: {e.reason}")
        return False
        
    except Exception as e:
        logger.warning(f"Unexpected error validating GitHub token: {e}")
        return False

def process_cve_files(cve_files: List[Path], output_file: Path, github_token: Optional[str] = None, aicg_api: Optional[str] = None, debug: bool = False) -> bool:
    """
    处理CVE文件并提取所需信息，分批处理并统计结果
    
    Args:
        cve_files: CVE JSON文件列表
        output_file: 输出CSV文件路径
        github_token: GitHub API token
        aicg_api: AI分类器配置字符串 (格式: api_url:model_name:api_key)
        debug: 是否输出调试信息
        
    Returns:
        bool: 处理是否成功
    """
    try:
        # 验证GitHub token
        if github_token and not _validate_github_token(github_token):
            logger.warning("Invalid GitHub token provided, proceeding without token")
            github_token = None
            
        # 解析AICG API配置
        aicg_config = _parse_aicg_api(aicg_api)
        if aicg_api and not aicg_config:
            logger.warning("Invalid AICG API configuration, falling back to heuristic classification")
            
        if debug:
            logger.info(f"Processing {len(cve_files)} CVE files")
            logger.info(f"Output file: {output_file}")
            logger.info(f"GitHub token provided: {bool(github_token)}")
            logger.info(f"AICG API config: {aicg_config}")
            
        # 按CVE ID排序文件
        logger.info("Sorting CVE files by CVE ID...")
        cve_files.sort(key=lambda x: x.stem)
        
        # 准备CSV输出
        fieldnames = ['cve_id', 'cwe_ids', 'github_repo', 'cur_commit', 'pre_commit', 'project_type']
        
        # 统计信息
        total_stats = {
            'total': len(cve_files),
            'processed': 0,
            'success': 0,
            'no_github_info': 0,  # 没有GitHub信息
            'no_php_files': 0,    # 没有PHP文件
            'invalid_repo': 0,    # 无效的仓库名称
            'api_error': 0,       # API错误
            'other_errors': 0,    # 其他错误
            'batch_number': 0
        }
        
        # 分批处理，每批5000个文件
        batch_size = 5000
        complete_rows = []
        
        # 创建进度显示
        progress = _create_progress()
        
        with progress:
            for i in range(0, len(cve_files), batch_size):
                total_stats['batch_number'] += 1
                batch_files = cve_files[i:i + batch_size]
                
                # 添加批次进度任务
                batch_task = progress.add_task(
                    f"[cyan]Processing batch {total_stats['batch_number']}",
                    total=len(batch_files),
                    status="Starting..."
                )
                
                # 重置批次统计
                batch_stats = {
                    'processed': len(batch_files),
                    'success': 0,
                    'no_github_info': 0,
                    'no_php_files': 0,
                    'invalid_repo': 0,
                    'api_error': 0,
                    'other_errors': 0
                }
                
                # 处理当前批次的文件
                for file_path in batch_files:
                    try:
                        progress.update(batch_task, advance=1, status=f"Processing {file_path.name}")
                        
                        if debug:
                            logger.info(f"\nProcessing file: {file_path.name}")
                        
                        # 读取CVE数据
                        with open(file_path, 'r', encoding='utf-8') as f:
                            cve_data = json.load(f)
                        
                        # 提取信息
                        cve_id = file_path.stem
                        cwe_id = _extract_cwe_id(cve_data=cve_data)
                        reference_data = cve_data.get('cve', {}).get('references', {}).get('reference_data', [])
                        
                        # 提取GitHub信息
                        repo, cur_commit, pre_commit = _extract_github_info(reference_data, github_token, cve_data)
                        
                        # 检查是否缺少GitHub信息
                        if not repo or not cur_commit or not pre_commit:
                            batch_stats['no_github_info'] += 1
                            total_stats['no_github_info'] += 1
                            continue
                        
                        # 验证仓库名称
                        if not _normalize_repo_name(repo):
                            batch_stats['invalid_repo'] += 1
                            total_stats['invalid_repo'] += 1
                            continue
                        
                        # 获取commit信息并检查PHP文件
                        commit_data = _get_commit_info(repo, cur_commit, github_token, progress, batch_task)
                        if not commit_data:
                            batch_stats['api_error'] += 1
                            total_stats['api_error'] += 1
                            continue
                            
                        patch_files = list(f.get('filename', '') for f in commit_data.get('files', []))
                        if not any(_is_php_file(f) for f in patch_files):
                            batch_stats['no_php_files'] += 1
                            total_stats['no_php_files'] += 1
                            continue
                        
                        # 确定项目类型
                        proj_type = _determine_project_type(repo, aicg_config)
                        
                        # 创建完整记录
                        row = {
                            'cve_id': cve_id,
                            'cwe_ids': cwe_id,
                            'github_repo': repo,
                            'cur_commit': cur_commit,
                            'pre_commit': pre_commit,
                            'project_type': proj_type
                        }
                        
                        # 只添加完整的记录
                        if all(row.values()):
                            complete_rows.append(row)
                            batch_stats['success'] += 1
                            total_stats['success'] += 1
                        
                        # 每处理100个文件输出一次统计
                        if len(complete_rows) % 100 == 0:
                            logger.info(
                                f"Progress: {len(complete_rows)} successful entries, "
                                f"NoGitHub={batch_stats['no_github_info']}, "
                                f"NoPHP={batch_stats['no_php_files']}, "
                                f"InvalidRepo={batch_stats['invalid_repo']}, "
                                f"APIError={batch_stats['api_error']}, "
                                f"OtherErrors={batch_stats['other_errors']}"
                            )
                        
                    except Exception as e:
                        batch_stats['other_errors'] += 1
                        total_stats['other_errors'] += 1
                        if debug:
                            logger.error(f"\nError processing {file_path.name}: {e}")
                
                # 先更新进度条状态为完成
                progress.update(batch_task, status=f"[green]Completed")
                
                # 添加换行，然后输出批次统计
                batch_start = i + 1
                batch_end = min(i + batch_size, total_stats['total'])
                logger.info(
                    f"\nBatch {total_stats['batch_number']} ({batch_start}-{batch_end}): "
                    f"Processed={batch_stats['processed']}, "
                    f"Success={batch_stats['success']}, "
                    f"NoGitHub={batch_stats['no_github_info']}, "
                    f"NoPHP={batch_stats['no_php_files']}, "
                    f"InvalidRepo={batch_stats['invalid_repo']}, "
                    f"APIError={batch_stats['api_error']}, "
                    f"OtherErrors={batch_stats['other_errors']}"
                )
                
                # 移除批次任务
                progress.remove_task(batch_task)
            
            # 写入CSV文件
            logger.info("\nWriting results to CSV...")
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(complete_rows)
            
            # 输出详细的最终统计信息
            total_processed = total_stats['total']
            total_success = total_stats['success']
            total_skipped = (total_stats['no_github_info'] + 
                           total_stats['no_php_files'] + 
                           total_stats['invalid_repo'] + 
                           total_stats['api_error'] + 
                           total_stats['other_errors'])
            
            logger.success("\n" + "="*50)
            logger.success("Final Processing Summary")
            logger.success("="*50)
            logger.info(f"\nOverall Statistics:")
            logger.info(f"  Total Files Processed: {total_processed}")
            logger.info(f"  Successfully Processed: {total_success} ({total_success/total_processed*100:.1f}%)")
            logger.info(f"  Total Skipped: {total_skipped} ({total_skipped/total_processed*100:.1f}%)")
            
            logger.info(f"\nDetailed Skip Reasons:")
            logger.info(f"  1. No GitHub Information: {total_stats['no_github_info']}")
            logger.info(f"     - Percentage: {total_stats['no_github_info']/total_processed*100:.1f}%")
            logger.info(f"     - These entries lack valid GitHub commit URLs or repository information")
            
            logger.info(f"\n  2. No PHP Files: {total_stats['no_php_files']}")
            logger.info(f"     - Percentage: {total_stats['no_php_files']/total_processed*100:.1f}%")
            logger.info(f"     - Commits found but contained no PHP-related files")
            
            logger.info(f"\n  3. Invalid Repository: {total_stats['invalid_repo']}")
            logger.info(f"     - Percentage: {total_stats['invalid_repo']/total_processed*100:.1f}%")
            logger.info(f"     - Repository names could not be normalized to owner/repo format")
            
            logger.info(f"\n  4. API Errors: {total_stats['api_error']}")
            logger.info(f"     - Percentage: {total_stats['api_error']/total_processed*100:.1f}%")
            logger.info(f"     - Failed to retrieve commit information from GitHub API")
            
            logger.info(f"\n  5. Other Errors: {total_stats['other_errors']}")
            logger.info(f"     - Percentage: {total_stats['other_errors']/total_processed*100:.1f}%")
            logger.info(f"     - Miscellaneous errors during processing")
            
            logger.info(f"\nOutput Information:")
            logger.info(f"  - CSV file: {output_file}")
            logger.info(f"  - Total successful entries written: {total_success}")
            logger.success("\n" + "="*50)
        
        return True
        
    except Exception as e:
        error_msg = f"Failed to process CVE files: {e}"
        if debug:
            logger.error(f"\n{error_msg}")
            logger.exception(e)
        else:
            logger.error(error_msg)
        return False
