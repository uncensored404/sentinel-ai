import json
from pathlib import Path
from typing import List, Dict
from datetime import datetime
from config import ALERT_LOG


class AlertManager:
    def __init__(self):
        self.alerts: List[Dict] = []
        self.max_alerts = 500

    def add(self, finding: Dict):
        self.alerts.insert(0, finding)
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[:self.max_alerts]

        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(finding, ensure_ascii=False) + "\n")

        sev = finding["severity"].upper()
        color = {
            "LOW": "\033[92m",
            "MEDIUM": "\033[93m",
            "HIGH": "\033[91m",
            "CRITICAL": "\033[95m"
        }.get(sev, "\033[0m")
        print(f"{color}[{sev}] {finding['title']}\033[0m → {finding['detail'][:120]}...")

    def get_recent(self, limit: int = 50) -> List[Dict]:
        return self.alerts[:limit]

    def get_stats(self) -> Dict:
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for a in self.alerts:
            counts[a["severity"]] = counts.get(a["severity"], 0) + 1
        return {
            "total": len(self.alerts),
            "by_severity": counts,
            "last_update": datetime.now().isoformat()
        }
