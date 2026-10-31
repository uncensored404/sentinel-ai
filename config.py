from pathlib import Path

# Chemins surveillés (ajoutez les vôtres)
MONITORED_PATHS = [
    Path(r"C:\Windows\System32"),
    Path(r"C:\Windows\SysWOW64"),
    Path(r"C:\Users"),
]

# Ports et processus suspects
SUSPICIOUS_PORTS = {4444, 5555, 6666, 8080, 1337, 31337, 12345, 4445, 55555}
SUSPICIOUS_PROCESSES = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe"
}

SEVERITY = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

POLL_INTERVAL = 8
ALERT_LOG = Path("sentinel_alerts.jsonl")
