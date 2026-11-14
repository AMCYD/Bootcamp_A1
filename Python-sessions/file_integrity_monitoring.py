import hashlib
import time
import os
from datetime import datetime

# Configuration Constants
TARGET_FILE = "system_config.conf"
SCAN_INTERVAL = 3      # Seconds between checks
CHUNK_SIZE = 4096      # 4KB chunks for efficient binary reading

def calculate_sha256(file_path):
    """Reads a file in binary chunks ('rb') and returns its SHA-256 hash."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

def start_fim(file_path):
    # Step 2: Establish the initial Baseline Hash
    baseline_hash = calculate_sha256(file_path)
    
    if baseline_hash is None:
        print(f"[ERROR] Target file '{file_path}' not found.")
        return

    print("=== File Integrity Monitoring (FIM) Active ===")
    print(f"Monitoring File : {file_path}")
    print(f"Baseline Hash   : {baseline_hash}")
    print(f"Check Interval  : Every {SCAN_INTERVAL} seconds\n")

    # Step 3: Continuous monitoring loop
    try:
        while True:
            time.sleep(SCAN_INTERVAL)
            current_hash = calculate_sha256(file_path)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Step 4 & 5: Compare hashes and trigger Critical Alert on mismatch
            if current_hash is None:
                print(f"[CRITICAL ALERT] [{timestamp}] Target file '{file_path}' was DELETED!")
                break
            elif current_hash != baseline_hash:
                print(f"\n[CRITICAL ALERT] [{timestamp}] Unauthorized modification detected in '{file_path}'!")
                print(f" -> Original Baseline Hash : {baseline_hash}")
                print(f" -> Modified Current Hash  : {current_hash}\n")
                baseline_hash = current_hash  # Update baseline to track subsequent edits
            else:
                print(f"[{timestamp}] Status: OK (No changes detected)")

    except KeyboardInterrupt:
        print("\n[INFO] File Integrity Monitoring stopped by administrator.")

if __name__ == "__main__":
    # Automatically creates a sample file if one does not exist for testing
    if not os.path.exists(TARGET_FILE):
        with open(TARGET_FILE, "w", encoding="utf-8") as f:
            f.write("ROOT_ACCESS=DISABLED\nFIREWALL=ENABLED\n")

    start_fim(TARGET_FILE)