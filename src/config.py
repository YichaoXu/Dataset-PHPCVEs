"""
Configuration module for PHP CVE Dataset Collection Tool.

This module provides configuration settings for the tool, including
PHP keywords, project types, and other settings.
"""

from typing import Dict, List, Any
import os
from pathlib import Path

# Get project root directory
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class Config:
    """Configuration settings for the PHP CVE Dataset Collection Tool."""
    
    def __init__(self):
        """Initialize configuration with default values."""
        # PHP-related keywords for filtering CVEs
        self.php_keywords = [
            "php", "wordpress", "drupal", "joomla", "laravel", "symfony", 
            "codeigniter", "cakephp", "zend", "magento", "prestashop", 
            "typo3", "phpbb", "mediawiki", "moodle", "nextcloud", "owncloud"
        ]
        
        # Project types and their associated keywords for classification
        self.project_types = {
            'Web App': {
                'web application': 3,
                'webapp': 3,
                'web app': 3,
                'website': 2,
                'web-based': 2,
                'web framework': 2,
                'cms': 2,
                'content management system': 2,
                'mvc': 1,
                'routes': 1
            },
            'CLI App': {
                'command line': 3,
                'cli': 3,
                'console': 2,
                'terminal': 2,
                'shell': 1,
                'command': 1
            },
            'Library': {
                'library': 3,
                'package': 2,
                'component': 2,
                'sdk': 2,
                'dependency': 1,
                'composer.json': 3
            },
            'Framework Plugin': {
                'plugin': 3,
                'extension': 2,
                'addon': 2,
                'module': 2
            },
            'Framework Theme': {
                'theme': 3,
                'template': 2,
                'skin': 2,
                'style': 1,
                'css': 1
            },
            'PHP-SRC': {
                'php-src': 5,
                'php source': 4,
                'php interpreter': 4,
                'zend engine': 4
            }
        }
        
        # Default paths
        self.default_cache_dir = Path(".inter")
        self.default_output_dir = Path("output")
        
        # API settings
        self.github_api_base_url = "https://api.github.com"
        self.nvd_api_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Rate limiting
        self.github_rate_limit_wait = True
        self.api_retry_count = 3
        self.api_retry_delay = 2  # seconds
        
        # Load environment variables
        self.github_token = os.environ.get("GITHUB_TOKEN")
        self.openai_api_key = os.environ.get("OPENAI_API_KEY")
        self.deepseek_api_key = os.environ.get("DEEPSEEK_API_KEY")

# Create a singleton instance
config = Config() 