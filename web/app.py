"""
Honeypot Dashboard  ·  FastAPI + Server-Sent Events
=====================================================
Started by main.py via:
    python main.py --open --dashboard

The dashboard thread shares the same Python process as the honeypot,
so core.threat_engine.event_queue is the SAME object in memory.
All live events flow through it automatically.
"""

from __future__ import annotations

import os, json, asyncio, threading, queue as _queue, datetime
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ── Import using sys.modules to guarantee same instance ──────────────────────
# By the time web/app.py loads, main.py has already imported core.threat_engine.
# We pull it from sys.modules so we get the EXACT same object, not a re-import.
import sys as _sys

def _get_te():
    """Return the already-loaded threat_engine module (same process instance)."""
    if "core.threat_engine" in _sys.modules:
        return _sys.modules["core.threat_engine"]
    # Fallback: load it normally (standalone / test mode)
    import importlib, pathlib
    root = str(pathlib.Path(__file__).parent.parent)
    if root not in _sys.path:
        _sys.path.insert(0, root)
    import core.threat_engine as te
    return te

_te = _get_te()

# Shorthand accessors — always read from the live module
def _event_queue():      return _te.event_queue
def _get_all_scores():   return _te.get_all_scores()
def _get_detail(ip):     return _te.get_session_detail(ip)
def _geoip(ip):          return _te.geoip_lookup(ip)

from database.db import DatabaseManager
from config.settings import DB_PATH

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(title="Honeypot Dashboard", docs_url=None, redoc_url=None)

_BASE         = os.path.dirname(__file__)
_STATIC_DIR   = os.path.join(_BASE, "static")
_TEMPLATE_DIR = os.path.join(_BASE, "templates")

app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
templates = Jinja2Templates(directory=_TEMPLATE_DIR)

db = DatabaseManager(DB_PATH)

# ── SSE client registry ───────────────────────────────────────────────────────
_clients: list[_queue.Queue] = []
_clients_lock = threading.Lock()


def _fanout_worker():
    """
    Background thread — runs forever.
    Reads from the shared threat_engine event_queue and copies
    every event into each connected browser client's queue.
    """
    eq = _event_queue()          # grab the shared queue once
    while True:
        try:
            ev = eq.get(timeout=1)
        except Exception:
            continue             # queue.Empty on timeout — loop again
        with _clients_lock:
            dead = []
            for q in _clients:
                try:
                    q.put_nowait(ev)
                except _queue.Full:
                    dead.append(q)
            for q in dead:
                try:    _clients.remove(q)
                except ValueError: pass


threading.Thread(target=_fanout_worker, daemon=True, name="sse-fanout").start()


# ══════════════════════════════════════════════════════════════════════════════
# HTML PAGES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/session/{ip}", response_class=HTMLResponse)
async def session_detail(request: Request, ip: str):
    return templates.TemplateResponse(
        "session_detail.html", {"request": request, "ip": ip}
    )


# ══════════════════════════════════════════════════════════════════════════════
# SERVER-SENT EVENTS  –  poll every 100 ms, no blocking
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/events")
async def sse_stream(request: Request):
    client_q: _queue.Queue = _queue.Queue(maxsize=500)
    with _clients_lock:
        _clients.append(client_q)

    async def generator() -> AsyncGenerator[str, None]:
        # Immediately confirm the connection to the browser
        yield f"data: {json.dumps({'event_type': 'connected'})}\n\n"
        hb = 0
        try:
            while True:
                if await request.is_disconnected():
                    break

                # Drain everything available right now — no blocking
                sent = 0
                while True:
                    try:
                        ev = client_q.get_nowait()
                        yield f"data: {json.dumps(ev)}\n\n"
                        sent += 1
                    except _queue.Empty:
                        break

                if sent:
                    hb = 0
                else:
                    await asyncio.sleep(0.1)    # 100 ms poll interval
                    hb += 1
                    if hb >= 150:               # heartbeat every ~15 s
                        yield "data: {\"event_type\":\"heartbeat\"}\n\n"
                        hb = 0
        finally:
            with _clients_lock:
                try:    _clients.remove(client_q)
                except ValueError: pass

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


# ══════════════════════════════════════════════════════════════════════════════
# REST API
# ══════════════════════════════════════════════════════════════════════════════

def _q(sql, *p):
    try:
        with db._lock:
            return db._conn.execute(sql, p).fetchone()[0]
    except Exception:
        return 0


@app.get("/api/stats")
async def api_stats():
    scores = _get_all_scores()
    return JSONResponse({
        "total_connections":    _q("SELECT COUNT(*) FROM connections"),
        "total_auth_attempts":  _q("SELECT COUNT(*) FROM auth_attempts"),
        "unique_ips":           _q("SELECT COUNT(DISTINCT source_ip) FROM connections"),
        "total_threats":        _q("SELECT COUNT(*) FROM threats"),
        "critical_threats":     _q("SELECT COUNT(*) FROM threats WHERE severity IN ('critical','high')"),
        "total_commands":       _q("SELECT COUNT(*) FROM commands"),
        "high_priority_alerts": _q("SELECT COUNT(*) FROM threats WHERE high_priority=1"),
        "active_sessions":      len(scores),
        "max_session_score":    max(scores.values(), default=0),
    })


@app.get("/api/threats/recent")
async def api_recent_threats():
    return JSONResponse(db.get_threats(limit=50))


@app.get("/api/threats/categories")
async def api_threat_categories():
    try:
        with db._lock:
            rows = db._conn.execute(
                "SELECT category, COUNT(*) cnt FROM threats GROUP BY category ORDER BY cnt DESC"
            ).fetchall()
        return JSONResponse([dict(r) for r in rows])
    except Exception:
        return JSONResponse([])


@app.get("/api/threats/timeline")
async def api_threat_timeline():
    try:
        with db._lock:
            rows = db._conn.execute(
                """SELECT strftime('%Y-%m-%dT%H:00:00', detected_at) hour,
                          COUNT(*) cnt
                   FROM threats
                   WHERE detected_at >= datetime('now','-24 hours')
                   GROUP BY hour ORDER BY hour"""
            ).fetchall()
        return JSONResponse([dict(r) for r in rows])
    except Exception:
        return JSONResponse([])


@app.get("/api/threats/severity_timeline")
async def api_severity_timeline():
    try:
        with db._lock:
            rows = db._conn.execute(
                """SELECT strftime('%H:00', detected_at) hour,
                          severity, COUNT(*) cnt
                   FROM threats
                   WHERE detected_at >= datetime('now','-24 hours')
                   GROUP BY hour, severity ORDER BY hour"""
            ).fetchall()
        return JSONResponse([dict(r) for r in rows])
    except Exception:
        return JSONResponse([])


@app.get("/api/attackers/top")
async def api_top_attackers():
    rows = db.get_top_attackers(limit=15)
    scores = _get_all_scores()
    enriched = []
    for r in rows:
        geo = _geoip(r["source_ip"])
        enriched.append({
            **r,
            "country": geo.get("country", "Unknown"),
            "city":    geo.get("city", ""),
            "isp":     geo.get("isp", "Unknown"),
            "lat":     geo.get("lat", 0.0),
            "lon":     geo.get("lon", 0.0),
            "score":   scores.get(r["source_ip"], 0),
        })
    return JSONResponse(enriched)


@app.get("/api/commands/top")
async def api_top_commands():
    return JSONResponse(db.get_top_commands(limit=20))


@app.get("/api/commands/recent")
async def api_recent_commands():
    try:
        with db._lock:
            rows = db._conn.execute(
                "SELECT source_ip, username, command, issued_at FROM commands "
                "ORDER BY issued_at DESC LIMIT 40"
            ).fetchall()
        return JSONResponse([dict(r) for r in rows])
    except Exception:
        return JSONResponse([])


@app.get("/api/scores")
async def api_scores():
    scores = _get_all_scores()
    result = []
    for ip, score in sorted(scores.items(), key=lambda x: -x[1]):
        geo = _geoip(ip)
        result.append({
            "ip":      ip,
            "score":   score,
            "country": geo.get("country", "Unknown"),
            "city":    geo.get("city", ""),
            "isp":     geo.get("isp", "Unknown"),
        })
    return JSONResponse(result)


@app.get("/api/geo/attackers")
async def api_geo_attackers():
    try:
        with db._lock:
            rows = db._conn.execute(
                "SELECT DISTINCT source_ip FROM connections"
            ).fetchall()
        scores = _get_all_scores()
        result = []
        for row in rows:
            ip  = row[0]
            geo = _geoip(ip)
            if not geo.get("is_private"):
                result.append({
                    "ip":      ip,
                    "lat":     geo.get("lat", 0),
                    "lon":     geo.get("lon", 0),
                    "country": geo.get("country", "Unknown"),
                    "city":    geo.get("city", ""),
                    "isp":     geo.get("isp", ""),
                    "score":   scores.get(ip, 0),
                })
        return JSONResponse(result)
    except Exception:
        return JSONResponse([])


@app.get("/api/alerts/high_priority")
async def api_high_priority():
    try:
        with db._lock:
            rows = db._conn.execute(
                "SELECT * FROM threats WHERE severity IN ('critical','high') "
                "ORDER BY detected_at DESC LIMIT 30"
            ).fetchall()
        return JSONResponse([dict(r) for r in rows])
    except Exception:
        return JSONResponse([])


# ── Session detail ────────────────────────────────────────────────────────────

@app.get("/api/session/{ip}/summary")
async def api_session_summary(ip: str):
    geo    = _geoip(ip)
    detail = _get_detail(ip)
    try:
        with db._lock:
            auth_rows = db._conn.execute(
                "SELECT username, password, success, attempted_at FROM auth_attempts "
                "WHERE source_ip=? ORDER BY attempted_at DESC LIMIT 50", (ip,)
            ).fetchall()
            cmd_rows = db._conn.execute(
                "SELECT command, issued_at FROM commands WHERE source_ip=? "
                "ORDER BY issued_at DESC LIMIT 100", (ip,)
            ).fetchall()
            threat_rows = db._conn.execute(
                "SELECT category, severity, command, message, session_score, detected_at "
                "FROM threats WHERE source_ip=? ORDER BY detected_at DESC LIMIT 50", (ip,)
            ).fetchall()
            conn_rows = db._conn.execute(
                "SELECT connected_at, disconnected_at FROM connections "
                "WHERE source_ip=? ORDER BY connected_at DESC LIMIT 10", (ip,)
            ).fetchall()
    except Exception:
        auth_rows = cmd_rows = threat_rows = conn_rows = []

    return JSONResponse({
        "ip":            ip,
        "geo":           geo,
        "score":         detail["score"],
        "commands":      detail["commands"],
        "category_hits": detail["hits"],
        "connections":   [dict(r) for r in conn_rows],
        "auth_attempts": [dict(r) for r in auth_rows],
        "commands_log":  [dict(r) for r in cmd_rows],
        "threats":       [dict(r) for r in threat_rows],
    })


@app.get("/api/session/{ip}/threat_timeline")
async def api_session_threat_timeline(ip: str):
    try:
        with db._lock:
            rows = db._conn.execute(
                """SELECT strftime('%H:%M', detected_at) minute,
                          category, COUNT(*) cnt
                   FROM threats WHERE source_ip=?
                   GROUP BY minute, category ORDER BY minute""",
                (ip,)
            ).fetchall()
        return JSONResponse([dict(r) for r in rows])
    except Exception:
        return JSONResponse([])


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT  (called from main.py in a daemon thread)
# ══════════════════════════════════════════════════════════════════════════════

def start_dashboard(host: str = "0.0.0.0", port: int = 5000):
    import uvicorn
    print(f"[*] Dashboard  → http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning", use_colors=False)


if __name__ == "__main__":
    # Direct run for testing only — live events won't flow without the honeypot
    start_dashboard()
