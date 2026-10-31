import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
import uvicorn
from datetime import datetime

from core.log_collector import LogCollector
from core.detectors import Detectors
from core.alert_manager import AlertManager
from core.file_monitor import FileMonitor
from config import POLL_INTERVAL

collector = LogCollector()
detectors = Detectors()
alerts = AlertManager()
file_monitor = None


async def monitoring_loop():
    print("[+] SENTINEL AI démarré — surveillance active (404sec)")
    while True:
        try:
            sysmon_events = collector.get_sysmon_events(60)
            security_events = collector.get_security_events(30)
            all_events = sysmon_events + security_events

            findings = detectors.analyze_events(all_events)
            for f in findings:
                alerts.add(f)

        except Exception as e:
            print(f"[!] Erreur monitoring: {e}")

        await asyncio.sleep(POLL_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global file_monitor
    file_monitor = FileMonitor(alerts.add)
    file_monitor.start()
    task = asyncio.create_task(monitoring_loop())
    yield
    task.cancel()
    file_monitor.stop()
    collector.close()


app = FastAPI(
    title="SENTINEL AI",
    description="Détection intelligente des cyberattaques - by 404sec",
    lifespan=lifespan
)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    stats = alerts.get_stats()
    recent = alerts.get_recent(40)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats,
        "alerts": recent,
        "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.get("/api/alerts")
async def api_alerts(limit: int = 50):
    return alerts.get_recent(limit)


@app.get("/api/stats")
async def api_stats():
    return alerts.get_stats()


@app.get("/api/health")
async def health():
    return {"status": "online", "service": "SENTINEL AI", "author": "404sec"}


if __name__ == "__main__":
    print("=" * 60)
    print("  SENTINEL AI — by 404sec")
    print("  Dashboard : http://127.0.0.1:8888")
    print("=" * 60)
    uvicorn.run("main:app", host="127.0.0.1", port=8888, reload=False)
