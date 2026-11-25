# Mini SOC Log Analyzer
 
A small Python project I built to practice basic cybersecurity concepts and log analysis.

It reads login events from a CSV file, counts successful and failed attempts, and flags IP addresses with repeated failed logins.

**Run it:**
```bash
python soc_analyzer.py
```
Uses fictional login data for testing.


## Log Format

The analyzer reads CSV log files with the following fields:

- `timestamp`: Date and time of the event.
- `event`: Type of activity (LOGIN_SUCCESS or LOGIN_FAILED).
- `username`: Account involved in the event.
- `ip`: IP address associated with the activity.

Example:

```csv
timestamp,event,username,ip
2026-11-25 08:00:00,LOGIN_SUCCESS,alice,192.168.1.10
2026-11-25 08:01:00,LOGIN_FAILED,admin,192.168.1.105
```
