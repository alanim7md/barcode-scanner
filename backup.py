import os
from datetime import datetime
import zipfile

# Files to protect
FILES_TO_BACKUP = ["database.db", "users.db"]
BACKUP_DIR = "backups"

if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
backup_filename = os.path.join(BACKUP_DIR, f"backup_{timestamp}.zip")

print(f"Starting backup at {timestamp}...")

with zipfile.ZipFile(backup_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for file in FILES_TO_BACKUP:
        if os.path.exists(file):
            zipf.write(file)
            print(f" -> Zipped {file}")
        else:
            print(f" -> Warning: {file} not found, skipping.")

print(f"Backup successfully saved to: {backup_filename}")
