# Dataset-PHPCVEs

A tool for collecting PHP-related CVE data with GitHub commit information.

## Features

- Downloads and extracts CVE data from the official CVE Project repository
- Filters for PHP-related vulnerabilities
- Extracts GitHub repository and commit information
- Determines project type (Web App, Framework Plugin, Library, etc.)
- Saves the dataset to a CSV file

## Installation

```bash
git clone https://github.com/yourusername/Dataset-PHPCVEs.git
cd Dataset-PHPCVEs
pip install -r requirements.txt
```

## Usage

### Collect CVE Data

```bash
python reproduce.py collect ./output --token YOUR_GITHUB_TOKEN
```

Options:
- `--token`: GitHub API token (optional, but recommended to avoid rate limits)
- `--no-cache`: Disable using cached dataset

### Download Code

```bash
python reproduce.py download ./output/dataset.csv ./code
```

### Generate Statistics

```bash
python reproduce.py statistic ./output/dataset.csv
```

### Clean Cache

```bash
python reproduce.py clean [cache_type]
```

Options:
- `cache_type`: Type of cache to clean (default: "all")
  - `all`: Clean all cache files
  - `collect`: Clean all collect command cache
  - `download`: Clean all download command cache
  - `statistic`: Clean all statistic command cache
  - `cve`: Clean only raw CVE data
  - `processed`: Clean only processed CVE cache

## Project Structure

```
Dataset-PHPCVEs/
├── reproduce.py                # Main entry point
├── src/
│   ├── commands/               # CLI commands
│   ├── core/                   # Core business logic
│   ├── models/                 # Data models
│   ├── utils/                  # Utility functions
│   └── config.py               # Configuration
├── .inter/                     # Intermediate files
└── output/                     # Output directory
```

## Requirements

- Python 3.8+
- Rich (for progress display)
- Typer (for CLI)
- Requests (for API calls)
