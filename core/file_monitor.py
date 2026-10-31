from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from typing import Callable
from config import MONITORED_PATHS


class SuspiciousFileHandler(FileSystemEventHandler):
    def __init__(self, alert_callback: Callable):
        self.alert_callback = alert_callback
        self.suspicious_extensions = {".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".scr"}

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path.lower()
        if any(path.endswith(ext) for ext in self.suspicious_extensions):
            self.alert_callback({
                "title": "Fichier exécutable créé",
                "detail": f"Nouveau fichier : {event.src_path}",
                "severity": "medium",
                "score": 2,
                "timestamp": datetime.now().isoformat(),
                "source_event": {"type": "file_monitor"}
            })


class FileMonitor:
    def __init__(self, alert_callback: Callable):
        self.observer = Observer()
        self.handler = SuspiciousFileHandler(alert_callback)

    def start(self):
        for path in MONITORED_PATHS:
            if path.exists():
                self.observer.schedule(self.handler, str(path), recursive=True)
        self.observer.start()
        print("[+] Surveillance fichiers démarrée")

    def stop(self):
        self.observer.stop()
        self.observer.join()
