import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "database.db")

def migrate():
    if not os.path.exists(DB_FILE):
        print(f"Error: Database file not found at {DB_FILE}")
        return

    print("Connecting to database...")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    try:
        # Check current columns in scans table
        c.execute("PRAGMA table_info(scans)")
        columns = [row[1] for row in c.fetchall()]
        print(f"Current columns in 'scans' table: {columns}")

        # Start transaction
        c.execute("BEGIN TRANSACTION;")

        # Add is_damaged column if it doesn't exist
        if "is_damaged" not in columns:
            print("Adding column 'is_damaged'...")
            c.execute("ALTER TABLE scans ADD COLUMN is_damaged INTEGER DEFAULT 0")
        else:
            print("Column 'is_damaged' already exists.")

        # Add is_flagged column if it doesn't exist
        if "is_flagged" not in columns:
            print("Adding column 'is_flagged'...")
            c.execute("ALTER TABLE scans ADD COLUMN is_flagged INTEGER DEFAULT 0")
        else:
            print("Column 'is_flagged' already exists.")

        # Update records where barcode contains __DAMAGED
        print("Flagging records with '__DAMAGED' suffix...")
        c.execute("UPDATE scans SET is_damaged = 1 WHERE barcode LIKE '%__DAMAGED%'")
        damaged_updated = c.rowcount
        print(f" -> Marked {damaged_updated} records as damaged.")

        # Update records where barcode contains __FLAGGED
        print("Flagging records with '__FLAGGED' suffix...")
        c.execute("UPDATE scans SET is_flagged = 1 WHERE barcode LIKE '%__FLAGGED%'")
        flagged_updated = c.rowcount
        print(f" -> Marked {flagged_updated} records as flagged.")

        # Clean barcodes (strip out __DAMAGED and __FLAGGED)
        print("Cleaning suffixes from barcode values...")
        c.execute("""
            UPDATE scans 
            SET barcode = REPLACE(REPLACE(barcode, '__DAMAGED', ''), '__FLAGGED', '')
            WHERE barcode LIKE '%__DAMAGED%' OR barcode LIKE '%__FLAGGED%'
        """)
        cleaned_count = c.rowcount
        print(f" -> Cleaned barcodes for {cleaned_count} records.")

        # Commit changes
        conn.commit()
        print("✅ Migration completed successfully!")

    except Exception as e:
        conn.rollback()
        print(f"❌ Migration failed and changes were rolled back: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
