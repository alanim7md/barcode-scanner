import os
import shutil
from datetime import datetime
import zipfile
import sqlite3
import csv

# --- CONFIGURATION ---
# Set this to the local path of your Google Drive folder. 
# Example: r"G:\My Drive\ScannerBackups" or r"C:\Users\alani\Google Drive\Backups"
GOOGLE_DRIVE_FOLDER = r"" 

DB_FILE = "database.db"
USERS_DB = "users.db"
BACKUP_DIR = "backups"
TEMP_DIR = "temp_csv_export"

def create_backup():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_filename = os.path.join(BACKUP_DIR, f"backup_{timestamp}.zip")

    print(f"Starting backup at {timestamp}...")

    files_to_zip = []
    if os.path.exists(DB_FILE): files_to_zip.append(DB_FILE)
    if os.path.exists(USERS_DB): files_to_zip.append(USERS_DB)

    # Export Branch/Session CSVs
    if os.path.exists(DB_FILE):
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT DISTINCT branch, session_name FROM scans WHERE session_name != ''")
            groups = c.fetchall()
            
            for branch, session_name in groups:
                safe_branch = str(branch).replace('/', '_').replace('\\', '_') if branch else "NoBranch"
                safe_session = str(session_name).replace('/', '_').replace('\\', '_')
                csv_path = os.path.join(TEMP_DIR, f"{safe_branch}_{safe_session}.csv")
                
                with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Barcode", "Good", "Damaged", "Flagged", "Last Scan"])
                    c.execute("""
                        SELECT REPLACE(REPLACE(barcode,'__DAMAGED',''),'__FLAGGED',''),
                               SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' AND barcode NOT LIKE '%__FLAGGED' THEN 1 ELSE 0 END),
                               SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
                               SUM(CASE WHEN barcode LIKE '%__FLAGGED' THEN 1 ELSE 0 END),
                               MAX(timestamp)
                        FROM scans 
                        WHERE branch=? AND session_name=? 
                        GROUP BY 1 ORDER BY MAX(timestamp) DESC
                    """, (branch, session_name))
                    for row in c.fetchall():
                        writer.writerow(row)
                files_to_zip.append(csv_path)
            conn.close()
        except Exception as e:
            print(f"Error generating CSVs: {e}")

    # Create the zip file
    with zipfile.ZipFile(backup_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in files_to_zip:
            if os.path.exists(file):
                zipf.write(file, arcname=os.path.basename(file))
                print(f" -> Zipped {os.path.basename(file)}")

    # Clean up temp CSVs
    if os.path.exists(TEMP_DIR):
        for f in os.listdir(TEMP_DIR):
            os.remove(os.path.join(TEMP_DIR, f))
        os.rmdir(TEMP_DIR)

    print(f"Local backup saved to: {backup_filename}")

    # Copy to Google Drive if configured
    if GOOGLE_DRIVE_FOLDER and os.path.exists(GOOGLE_DRIVE_FOLDER):
        try:
            drive_dest = os.path.join(GOOGLE_DRIVE_FOLDER, f"backup_{timestamp}.zip")
            shutil.copy2(backup_filename, drive_dest)
            print(f"✅ Successfully copied to Google Drive: {drive_dest}")
        except Exception as e:
            print(f"❌ Failed to copy to Google Drive: {e}")
    else:
        print("⚠️ Google Drive folder not configured or not found. Kept locally only.")

if __name__ == "__main__":
    create_backup()
