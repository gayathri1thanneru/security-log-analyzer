"""
Security Log Analyzer & Brute-Force Detector

Main application entry point.
"""

from pathlib import Path
import argparse

from detector import detect_brute_force, detect_failed_logins
from parser import load_log_file
from report import generate_summary, save_report


BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = BASE_DIR / "sample_logs" / "authentication_logs.csv"
REPORT_FILE = BASE_DIR / "reports" / "security_report.txt"


def main():
    """
    Run the Security Log Analyzer.
    """

    parser = argparse.ArgumentParser(
        description="Security Log Analyzer"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Number of failed attempts required to trigger an alert"
    )

    args = parser.parse_args()

    events = load_log_file(LOG_FILE)

    failed_logins = detect_failed_logins(events)

    alerts = detect_brute_force(
        events,
        threshold=args.threshold
    )

    total_events = len(events)

    generate_summary(
        total_events,
        failed_logins,
        alerts
    )

    save_report(
        total_events,
        failed_logins,
        alerts,
        REPORT_FILE
    )

    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
