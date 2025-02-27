"""
Configuration module for PHP CVE Dataset Collection Tool.

This module provides configuration settings for the application.
"""

from pathlib import Path

# Base directories - only essential paths
BASE_DIR = Path(__file__).parent.parent
CACHE_DIR = BASE_DIR / "cache"
INTER_DIR = BASE_DIR / ".inter"

# PHP keywords for filtering CVEs
php_keywords = [
    "php", 
    "wordpress", 
    "drupal", 
    "joomla", 
    "magento", 
    "laravel", 
    "symfony", 
    "codeigniter", 
    "cakephp", 
    "zend"
]

# Project type classification keywords and weights
project_types = {
    "Web App": {
        "web application": 10,
        "web app": 10,
        "webapp": 8,
        "cms": 8,
        "content management": 8,
        "ecommerce": 8,
        "e-commerce": 8,
        "online store": 8,
        "blog": 5,
        "website": 5
    },
    "Framework": {
        "framework": 10,
        "mvc": 8,
        "model-view-controller": 8,
        "application framework": 10,
        "web framework": 10
    },
    "Framework Plugin": {
        "plugin": 10,
        "extension": 8,
        "addon": 8,
        "add-on": 8,
        "module": 5,
        "wordpress plugin": 10,
        "drupal module": 10,
        "joomla extension": 10
    },
    "Framework Theme": {
        "theme": 10,
        "template": 8,
        "skin": 5,
        "wordpress theme": 10,
        "drupal theme": 10,
        "joomla template": 10
    },
    "Library": {
        "library": 10,
        "package": 8,
        "component": 5,
        "helper": 5,
        "utility": 5,
        "composer": 8
    },
    "CLI App": {
        "cli": 10,
        "command line": 10,
        "console": 8,
        "terminal": 8,
        "shell": 5
    },
    "PHP-SRC": {
        "php-src": 15,
        "php source": 15,
        "php interpreter": 15,
        "php language": 15,
        "php core": 15,
        "zend engine": 15
    }
}

# API rate limiting settings
github_rate_limit_wait = True
api_retry_count = 3
api_retry_delay = 2  # seconds

# Create a singleton instance
config = {
    "php_keywords": php_keywords,
    "project_types": project_types,
    "BASE_DIR": BASE_DIR,
    "CACHE_DIR": CACHE_DIR,
    "INTER_DIR": INTER_DIR,
    "github_rate_limit_wait": github_rate_limit_wait,
    "api_retry_count": api_retry_count,
    "api_retry_delay": api_retry_delay
} 