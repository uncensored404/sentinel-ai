import win32evtlog
import win32evtlogutil
from typing import List, Dict


class LogCollector:
    def __init__(self):
        self.handles = {}

    def open_log(self, log_name: str):
        try:
            handle = win32evtlog.OpenEventLog(None, log_name)
            self.handles[log_name] = handle
            return handle
        except Exception as e:
            print(f"[!] Impossible d'ouvrir {log_name}: {e}")
            return None

    def read_events(self, log_name: str, max_events: int = 50) -> List[Dict]:
        handle = self.handles.get(log_name) or self.open_log(log_name)
        if not handle:
            return []

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = []

        try:
            while len(events) < max_events:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                for event in records:
                    events.append(self._parse_event(event, log_name))
                    if len(events) >= max_events:
                        break
        except Exception as e:
            print(f"[!] Erreur lecture {log_name}: {e}")

        return events

    def _parse_event(self, event, log_name: str) -> Dict:
        try:
            return {
                "log": log_name,
                "event_id": event.EventID & 0xFFFF,
                "time": event.TimeGenerated.Format(),
                "source": event.SourceName,
                "computer": event.ComputerName,
                "message": win32evtlogutil.SafeFormatMessage(event, log_name) or "",
                "raw": str(event.StringInserts) if event.StringInserts else ""
            }
        except Exception:
            return {"log": log_name, "event_id": 0, "message": "parse error"}

    def get_sysmon_events(self, max_events: int = 80) -> List[Dict]:
        return self.read_events("Microsoft-Windows-Sysmon/Operational", max_events)

    def get_security_events(self, max_events: int = 50) -> List[Dict]:
        return self.read_events("Security", max_events)

    def close(self):
        for handle in self.handles.values():
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass
