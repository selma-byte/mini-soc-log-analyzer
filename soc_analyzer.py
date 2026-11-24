
import csv
from collections import Counter

# Configuration
LOG_FILE = "sample_logs.csv"
ALERT_THRESHOLD = 5


def analyze_logs():

    failed_attempts = Counter()
    successful_attempts = 0
    total_attempts = 0

    print("\n" + "=" * 45)
    print("          MINI SOC LOG ANALYZER")
    print("=" * 45)

    try:
        with open(LOG_FILE, "r", newline="") as file:

            reader = csv.DictReader(file)

            for row in reader:

                event = row["event"].strip()
                ip = row["ip"].strip()

                if not ip:
                    continue

                total_attempts += 1

                if event == "LOGIN_FAILED":
                    failed_attempts[ip] += 1

                elif event == "LOGIN_SUCCESS":
                    successful_attempts += 1

    except FileNotFoundError:
        print("\n[ERROR] Log file not found!")
        print("Make sure sample_logs.csv exists.")
        return

    except (KeyError, csv.Error) as error:
        print("\n[ERROR] Invalid log file:", error)
        return

    # Calculate statistics
    total_failed = sum(failed_attempts.values())

    print("\n[+] LOG ANALYSIS SUMMARY")
    print("-" * 45)

    print(f"Total login attempts : {total_attempts}")
    print(f"Successful logins    : {successful_attempts}")
    print(f"Failed logins        : {total_failed}")
    print(f"Unique IP addresses  : {len(failed_attempts)}")

    # Detect suspicious IP addresses
    print("\n[!] SECURITY ALERTS")
    print("-" * 45)

    suspicious_ips = {
        ip: count
        for ip, count in failed_attempts.items()
        if count >= ALERT_THRESHOLD
    }

    if suspicious_ips:

        for ip, count in suspicious_ips.items():

            print(f"\n[SUSPICIOUS] IP: {ip}")
            print(f"Failed attempts: {count}")
            print("Possible brute-force activity detected.")

    else:
        print("No suspicious login activity detected.")

    # Show most active failed-login sources
    print("\n[+] TOP FAILED-LOGIN SOURCES")
    print("-" * 45)

    if failed_attempts:
        for ip, count in failed_attempts.most_common(5):
            print(f"{ip:<20} {count} failed attempts")
    else:
        print("No failed login attempts found.")

    print("\n" + "=" * 45)
    print("          ANALYSIS COMPLETED")
    print("=" * 45)


# Start the application
if __name__ == "__main__":
    analyze_logs()
