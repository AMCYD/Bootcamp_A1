import re

# Step 2: Define attack patterns using re.compile() with re.IGNORECASE
ATTACK_PATTERNS = {
    "SQL Injection": re.compile(
        r"(UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|SELECT\s+\*\s+FROM|'--|%27)",
        re.IGNORECASE
    ),
    "Path Traversal": re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|boot\.ini|win\.ini)",
        re.IGNORECASE
    ),
    "Cross-Site Scripting (XSS)": re.compile(
        r"(<script>|alert\(|onerror=|onload=|javascript:)",
        re.IGNORECASE
    ),
    "Command Injection": re.compile(
        r"(;\s*cat\s+|;\s*ls\s+|\|\s*whoami|&&\s*id)",
        re.IGNORECASE
    )
}

# Pattern to extract the attacker's IPv4 address from the log line
IP_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

def analyze_logs(file_path):
    attack_summary = {attack_type: 0 for attack_type in ATTACK_PATTERNS}
    total_alerts = 0

    print("=== SOC Automated Web Server Log Analyzer ===\n")

    try:
        # Step 1: Read the log file line-by-line using with open()
        with open(file_path, "r", encoding="utf-8") as log_file:
            # Step 3: Iterate through log lines
            for line_number, line in enumerate(log_file, start=1):
                line = line.strip()
                if not line:
                    continue

                ip_match = IP_PATTERN.search(line)
                attacker_ip = ip_match.group(1) if ip_match else "Unknown IP"

                # Apply all detection patterns to the current line
                for attack_name, pattern in ATTACK_PATTERNS.items():
                    if pattern.search(line):
                        total_alerts += 1
                        attack_summary[attack_name] += 1

                        # Step 4: Print custom security alert
                        print(f"[SECURITY ALERT] Attack Detected: {attack_name}")
                        print(f" -> Line Number : {line_number}")
                        print(f" -> Attacker IP : {attacker_ip}")
                        print(f" -> Raw Log     : {line}\n")

    except FileNotFoundError:
        print(f"[ERROR] Log file '{file_path}' not found.")
        return

    # Step 5: Display final summary report
    print("=" * 50)
    print("FINAL SCAN SUMMARY")
    print("=" * 50)
    print(f"Total Attacks Detected: {total_alerts}\n")
    print("Breakdown by Attack Type:")
    for attack_name, count in attack_summary.items():
        print(f" - {attack_name}: {count}")
    print("=" * 50)

if __name__ == "__main__":
    analyze_logs("amer.log")