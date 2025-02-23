# Dataset PHPCVEs

## 1. Overview
This dataset contains the five most frequently occurring vulnerabilities from [CVEListV5@2025-02-14_1700Z](https://github.com/CVEProject/cvelistV5). To ensure efficiency, we only included vulnerabilities that are available on GitHub.

### 1.1 Filtering Criteria
The CVEs in this dataset were selected based on the following criteria:
1. The CVE record in **CVEListV5** contains **PHP-related keywords**.
2. The **refers** section of the CVE record includes a **GitHub patch link**.
3. The **GitHub patch** contains at least one **PHP-related file** (e.g., `.php`).

### 1.2 Dataset Composition
The dataset consists of:
- **236** instances of XSS (CWE-79)
- **98** instances of SQL Injection (CWE-89)
- **19** instances of Unrestricted File Upload (CWE-434)
- **13** instances of Code Injection (CWE-94)
- **13** instances of Command Injection (CWE-77 & CWE-78)

The dataset is categorized by year, and ground truth labels are provided.

## 2. Download

### OPTION-1 Download released zip files for the dataset
You can find the downloadable zip files under the [release page](https://github.com/YichaoXu/Dataset-PHPCVEs/releases)

### OPTION-2 Download dataset by a Python Script 
A Python script (`reproduce.py`) is provided to automate dataset retrieval and ensure reproducibility. 
**Please notice that the docker engine is still required for this script.**

#### Example Usage:
```sh
$ pip install -r requirements.txt
$ python reproduce.py install    # Build the Docker image
$ python reproduce.py download --output data_storage_dir --token YOUR_GITHUB_TOKEN # Download dataset
$ python reproduce.py clean      # Remove Docker image
```

### OPTION-3 Download dataset by a Docker container
To build and run the dataset container, execute the following commands:

#### Example Usage:
```sh
$ cd docker
$ docker build -t cves-dataset .
$ docker run --rm \
    -v "$(pwd)/output:/output" \
    -e GITHUB_TOKEN=? \
    cves-dataset
```
After execution, the projects will be downloaded into the `output` directory.

### Important Notes
- If a repository is renamed or removed after this date, the dataset may differ.
- For consistency, we recommend using zip format of the dataset provided in the release page.

## Contact
For questions or issues, please contact the project maintainer.