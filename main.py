import os
import time
import subprocess
import datetime
import shutil
from croniter import croniter

# --- Configuration ---
BACKUP_DIR = "/backups"
STATE_FILE = os.path.join(BACKUP_DIR, "last_run.txt")
TOKEN_FILE = os.getenv("GITHUB_TOKEN_FILE")
USER = os.getenv("GITHUB_USER")
CRON_SCHEDULE = os.getenv("BACKUP_SCHEDULE", "0 5 * * *")

def get_token():
    if TOKEN_FILE and os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            return f.read().strip()
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return token
    raise ValueError("No GITHUB_TOKEN or GITHUB_TOKEN_FILE found.")

def clean_broken_repos():
    """Removes directories that aren't valid git repositories."""
    if not os.path.exists(BACKUP_DIR):
        return
    for item in os.listdir(BACKUP_DIR):
        repo_path = os.path.join(BACKUP_DIR, item)
        if os.path.isdir(repo_path) and not os.path.exists(os.path.join(repo_path, '.git')):
            print(f"[WARN] Found broken folder '{item}'. Deleting...")
            shutil.rmtree(repo_path)

def should_run(cron_str):
    if not os.path.exists(STATE_FILE):
        return True # Never run, start now

    with open(STATE_FILE, 'r') as f:
        try:
            last_run_ts = float(f.read().strip())
            last_run_dt = datetime.datetime.fromtimestamp(last_run_ts)
        except Exception as e:
            print(f"[ERROR] Reading state file: {e}")
            return True
        
        # Find the next scheduled run that should have happened after the last successful run
        iter = croniter(cron_str, last_run_dt)
        next_scheduled = iter.get_next(datetime.datetime)
        now = datetime.datetime.now()
        return now >= next_scheduled

def run_backup():
    print(f"[{datetime.datetime.now()}] Starting Sync...")
    clean_broken_repos()
    
    try:
        token = get_token()
        cmd = [
            "github-backup", USER,
            "--token", token,
            "--output-directory", BACKUP_DIR,
            "--all", "--incremental", "--private", "--repositories"
        ]
        subprocess.run(cmd, check=True)
        
        # Save completion time
        with open(STATE_FILE, 'w') as f:
            f.write(str(time.time()))
        print(f"[{datetime.datetime.now()}] Backup Successful.")
    except Exception as e:
        print(f"[{datetime.datetime.now()}] Backup Failed: {e}")

if __name__ == "__main__":
    print(f"--- Service Started (User: {USER}, Schedule: {CRON_SCHEDULE}) ---")
    while True:
        if should_run(CRON_SCHEDULE):
            run_backup()
        # Check every 30 seconds to stay precise
        time.sleep(30)