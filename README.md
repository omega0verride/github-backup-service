# GitHub Backup Service

A lightweight automation service that performs incremental backups of all repositories in a GitHub account. It uses a cron-based scheduler to pull public and private repositories and includes a self-healing mechanism to remove corrupted repository folders.  
Can be used as a way to backup your account repos (just in case).  
Based on https://github.com/josegonzalez/python-github-backup. 

---

## Configuration Options

The following environment variables are available:

| Variable | Default | Description |
| :--- | :--- | :--- |
| **GITHUB_USER** | *Required* | The GitHub username or organization to back up. |
| **GITHUB_TOKEN** | *Required* | GitHub Personal Access Token (PAT) with repository access. |
| **GITHUB_TOKEN_FILE** | `None` | Optional path to a file containing the token (for secret management). |
| **BACKUP_SCHEDULE** | `0 5 * * *` | Cron-style schedule. Defaults to **5:00 AM every day**. |
| **DATA_DIR** | `./data/backups` | Host path where repositories and the state file are stored. |
---