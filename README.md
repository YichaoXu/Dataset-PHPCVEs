# Dataset PHPCVEs

## 1. Overview

This dataset comprises a collection of GitHub repository source codes for PHP web applications, specifically focusing on the five most prevalent taint-style vulnerabilities as identified in [CVEListV5@2025-02-14_1700Z](https://github.com/CVEProject/cvelistV5).

### 1.1 Filtering Criteria

| Step | Criteria | Description |
|------|----------|-------------|
| 1 | CVE Content | Record in **CVEListV5** contains **PHP-related keywords** |
| 2 | Reference Check | The **refers** section includes a **GitHub patch link** |
| 3 | File Validation | The **GitHub patch** contains at least one **PHP file** (`.php`) |
| 4 | Project Type | Repository is classified as `Web App` by [repo-classifier](https://github.com/YichaoXu/repo_classifier/tree/main) |

### 1.2 Dataset Composition

| CWE Type | Description | Count | Percentage |
|----------|-------------|-------|------------|
| CWE-79   | Cross-site Scripting (XSS) | 190 | 60.9% |
| CWE-89   | SQL Injection | 83 | 26.6% |
| CWE-434  | Unrestricted File Upload | 15 | 4.8% |
| CWE-94   | Code Injection | 14 | 4.5% |
| CWE-77   | Command Injection | 10 | 3.2% |

## 2. Download

### OPTION-1 Download released zip files for the dataset
You can find the downloadable zip files under the [release page](https://github.com/YichaoXu/Dataset-PHPCVEs/releases)

### OPTION-2 Download dataset by a Python Script

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Download dataset:
```bash
python reproduce.py download \
    .cache/collected.csv \
    ./output \
    --project-types "Web App" \
    --cwe-types "79,89,434,94,77" \
```

Parameters:
- `collected.csv`: Input file containing CVE data
- `./output`: Output directory for downloaded repositories
- `--project-types`: Filter by project type (e.g., "Web App")
- `--cwe-types`: Filter by CWE types
The dataset will be downloaded and organized as `output_dir/CWE-ID/CVE-ID/`.

### Important Notes
- If a repository is renamed or removed after this date, the dataset may differ.
- For consistency, we recommend using zip format of the dataset provided in the release page.
- Please also consider to cite our paper, if you used this dataset in your work

## Contact
For questions or issues, please contact the project maintainer.
