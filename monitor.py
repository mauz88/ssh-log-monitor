import subprocess
import re
from datetime import datetime

# Patterns to look for
ALERT_PATTERNS = [
    r"Failed password",
    r"Invalid user",
    r"Connection closed by invalid user",
    r"authentication failure",
]

def get_ssh_logs():
    try:
        # Get last 50 lines of SSHD logs
        result = subprocess.run(
            ["journalctl", "-u", "sshd", "--no-pager", "-n", "50"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.splitlines()
    except Exception as e:
        print(f"[ERROR] Could not read logs: {e}")
        return []

def analyze_logs(log_lines):
    alerts = []
    for line in log_lines:
        for pattern in ALERT_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                alerts.append(line)
    return alerts

def main():
    logs = get_ssh_logs()
    suspicious = analyze_logs(logs)
    print(f"\n--- SSH Log Monitor: {datetime.now()} ---")
    if suspicious:
        print("[!] Suspicious activity found:")
        for alert in suspicious:
            print(f"  > {alert}")
    else:
        print("No suspicious activity detected.")

if __name__ == "__main__":
    main()

