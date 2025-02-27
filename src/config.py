from pathlib import Path

class Config:
    """Global configuration"""
    def __init__(self):
        self.cache_dir = Path("caches")
        self.cve_url = "https://github.com/CVEProject/cvelistV5/releases/download/cve_2025-02-14_1700Z/2025-02-14_all_CVEs_at_midnight.zip.zip"
        self.php_keywords = ["php", ".php", "zend", "laravel", "wordpress", "drupal", "joomla"]
        self.github_api_url = "https://api.github.com"
        
        # Known projects mapping
        self.known_projects = {
            'wordpress': 'Web App',
            'wordpress-plugin': 'Framework Plugin',
            'wp-plugin': 'Framework Plugin',
            'wordpress-theme': 'Framework Theme',
            'wp-theme': 'Framework Theme',
            'drupal': 'Web App',
            'drupal-module': 'Framework Plugin',
            'drupal-theme': 'Framework Theme',
            'joomla': 'Web App',
            'joomla-plugin': 'Framework Plugin',
            'joomla-template': 'Framework Theme',
            'php-src': 'PHP-SRC',
            'laravel': 'Web App',
            'symfony': 'Web App',
            'composer': 'CLI App',
            'magento': 'Web App',
            'prestashop': 'Web App',
            'moodle': 'Web App'
        }
        
        # Project type keywords with weights
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

config = Config() 