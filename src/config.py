"""
Configuration module for PHP CVE Dataset Collection Tool.

This module provides configuration settings for the application.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

@dataclass(frozen=True)
class PHPCVEConfig:
    """Configuration for PHP CVE Collection Tool."""
    
    # Base directories
    base_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent)
    cache_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / ".cache")
    inter_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / ".inter")
    
    # PHP keywords for filtering CVEs
    php_keywords: List[str] = field(default_factory=lambda: [
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
    ])
    
    # API rate limiting settings
    github_rate_limit_wait: bool = True
    api_retry_count: int = 3
    api_retry_delay: int = 2  # seconds
    
    # Project type classification keywords and weights
    project_types: Dict[str, Dict[str, int]] = field(default_factory=lambda: {
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
    })

# Create a singleton instance
config = PHPCVEConfig() 