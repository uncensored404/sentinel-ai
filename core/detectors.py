from datetime import datetime
from typing import List, Dict
import re
from config import SUSPICIOUS_PORTS, SUSPICIOUS_PROCESSES, SEVERITY


class Detectors:
    def analyze_events(self, events: List[Dict]) -> List[Dict]:
        findings = []
        for evt in events:
            findings.extend(self._check_event(evt))
        return findings

    def _check_event(self, evt: Dict) -> List[Dict]:
        results = []
        eid = evt.get("event_id", 0)
        msg = (evt.get("message") or "") + " " + (evt.get("raw") or "")
        msg_lower = msg.lower()

        # Sysmon Event ID 1 - Process Creation
        if eid == 1:
            for proc in SUSPICIOUS_PROCESSES:
                if proc in msg_lower:
                    results.append(self._make_finding(
                        "Processus suspect lancé",
                        f"Processus : {proc} | {msg[:300]}",
                        "high",
                        evt
                    ))

            if "powershell" in msg_lower and ("-enc" in msg_lower or "-e " in msg_lower or "frombase64" in msg_lower):
                results.append(self._make_finding(
                    "PowerShell potentiellement obfuscqué",
                    msg[:400],
                    "critical",
                    evt
                ))

        # Sysmon Event ID 3 - Network Connection
        if eid == 3:
            for port in SUSPICIOUS_PORTS:
                if f":{port}" in msg or f" {port} " in msg:
                    results.append(self._make_finding(
                        "Connexion vers port suspect",
                        f"Port {port} détecté | {msg[:300]}",
                        "high",
                        evt
                    ))

            if re.search(r"\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)", msg):
                if any(p in msg_lower for p in ["powershell", "cmd", "wscript", "mshta"]):
                    results.append(self._make_finding(
                        "Connexion réseau suspecte depuis process détourné",
                        msg[:350],
                        "critical",
                        evt
                    ))

        # Sysmon Event ID 11 - FileCreate
        if eid == 11:
            if any(ext in msg_lower for ext in [".exe", ".dll", ".ps1", ".bat", ".vbs", ".js"]):
                if any(x in msg_lower for x in ["temp", "appdata", "downloads", "public"]):
                    results.append(self._make_finding(
                        "Création de fichier exécutable dans zone sensible",
                        msg[:350],
                        "medium",
                        evt
                    ))

        # Sysmon Event ID 13 - Registry
        if eid == 13:
            if "run" in msg_lower or "currentversion\\run" in msg_lower:
                results.append(self._make_finding(
                    "Modification de clé de démarrage (persistance)",
                    msg[:350],
                    "high",
                    evt
                ))

        # Security Log
        if evt.get("log") == "Security" and eid in (4625, 4648, 4672):
            results.append(self._make_finding(
                "Événement d'authentification sensible",
                msg[:300],
                "medium" if eid == 4625 else "high",
                evt
            ))

        return results

    def _make_finding(self, title: str, detail: str, severity: str, evt: Dict) -> Dict:
        return {
            "title": title,
            "detail": detail,
            "severity": severity,
            "score": SEVERITY.get(severity, 1),
            "timestamp": datetime.now().isoformat(),
            "source_event": {
                "log": evt.get("log"),
                "event_id": evt.get("event_id"),
                "time": evt.get("time")
            }
        }
