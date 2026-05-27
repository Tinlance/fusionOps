#!/usr/bin/env python3
"""
FusionOps API – Tinlance Limited
github.com/Tinlance/fusionops

This file belongs in the FusionOps repo (NOT the ThreatFade repo).
It calls ThreatFade as an external HTTP service — no direct imports.

Run:
    pip install -r requirements.txt
    uvicorn api.fusionops_api:app --host 0.0.0.0 --port 8080 --reload

Then open: http://localhost:8080/docs

ThreatFade must be running separately on port 8000.
Set THREATFADE_API_URL in your .env file.
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import tempfile
import os
import uuid
import httpx

# ── Load config ───────────────────────────────────────────────────────────────
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import settings

# ── Triage agent (local to FusionOps) ────────────────────────────────────────
from agents.triage_agent import run_triage

# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="FusionOps API – Tinlance Limited",
    description=(
        "Agentic SecOps + AIOps convergence platform. "
        "Calls ThreatFade for C2 detection, then runs triage and remediation agents. "
        "Validated against real Merlin QUIC C2 malware traffic (z-score 14.76)."
    ),
    version="0.3.0",
    contact={
        "name": "Tinlance Limited",
        "url": "https://github.com/Tinlance/fusionops"
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # Lock down to dashboard domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory event log (replace with DynamoDB/Postgres in production) ────────
_event_log: List[dict] = []
MAX_EVENTS = 200

def _log_event(event: dict):
    _event_log.append(event)
    if len(_event_log) > MAX_EVENTS:
        _event_log.pop(0)

# ── Pydantic models ───────────────────────────────────────────────────────────

class SignalPayload(BaseModel):
    timestamps: List[float] = Field(
        ..., description="Unix timestamps as floats e.g. [1710000000.0, ...]"
    )
    values: List[float] = Field(
        ..., description="Signal entropy values e.g. [3.12, 2.98, ...]"
    )
    source_label: Optional[str] = Field(
        None, description="Human label for this data source e.g. 'prod-server-01'"
    )

class ScenarioRequest(BaseModel):
    scenario: str = Field(
        "mixed",
        description="One of: c2_quieting | lotl_gradual | gnss_jam | normal_with_fade | mixed"
    )

class DetectionResult(BaseModel):
    event_id: str
    timestamp: str
    source: str
    detected: bool
    score: float
    entropy: float
    drop_ratio: float
    z_outlier: float
    fade_start: Optional[int]
    mitre_ttp: Optional[str]
    volatility_artifacts: Optional[str]
    severity: str

class FullAnalysisResult(BaseModel):
    """Combined detection + triage result — the main FusionOps output."""
    detection: DetectionResult
    triage: dict

# ── ThreatFade HTTP client ─────────────────────────────────────────────────────

async def _call_threatfade(endpoint: str, payload: dict) -> dict:
    """
    Call a ThreatFade API endpoint and return the JSON response.
    Raises HTTPException with a clear message if ThreatFade is unreachable.
    """
    url = f"{settings.threatfade_api_url}{endpoint}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return response.json()
    except httpx.ConnectError:
        raise HTTPException(
            503,
            f"Cannot reach ThreatFade at {settings.threatfade_api_url}. "
            "Make sure ThreatFade is running and THREATFADE_API_URL is set correctly in .env"
        )
    except httpx.TimeoutException:
        raise HTTPException(504, "ThreatFade request timed out after 30 seconds")
    except httpx.HTTPStatusError as e:
        raise HTTPException(502, f"ThreatFade returned error: {e.response.text}")


async def _call_threatfade_pcap(pcap_path: str, filename: str) -> dict:
    """Upload a PCAP file to ThreatFade and return detection result."""
    url = f"{settings.threatfade_api_url}/detect/pcap"
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            with open(pcap_path, "rb") as f:
                response = await client.post(
                    url,
                    files={"file": (filename, f, "application/octet-stream")}
                )
            response.raise_for_status()
            return response.json()
    except httpx.ConnectError:
        raise HTTPException(
            503,
            f"Cannot reach ThreatFade at {settings.threatfade_api_url}. "
            "Make sure ThreatFade is running."
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(502, f"ThreatFade PCAP analysis failed: {e.response.text}")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    """
    FusionOps liveness check.
    Also pings ThreatFade to confirm the full pipeline is up.
    """
    threatfade_status = "unknown"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.threatfade_api_url}/health")
            threatfade_status = "ok" if r.status_code == 200 else "error"
    except Exception:
        threatfade_status = "unreachable"

    return {
        "status": "ok",
        "service": "FusionOps API",
        "version": "0.3.0",
        "threatfade": threatfade_status,
        "threatfade_url": settings.threatfade_api_url,
        "environment": settings.fusionops_env,
    }


@app.get("/events", tags=["Monitoring"])
def get_events(limit: int = 50):
    """
    Return the last N full analysis events (detection + triage).
    This is the feed your dashboard polls every few seconds.
    """
    return {
        "events": _event_log[-limit:],
        "total": len(_event_log),
        "detections": sum(1 for e in _event_log if e.get("detection", {}).get("detected")),
    }


@app.post("/detect/json", response_model=FullAnalysisResult, tags=["Detection"])
async def detect_from_json(payload: SignalPayload):
    """
    Analyse signal data passed as JSON.

    1. Calls ThreatFade /detect/json for C2 detection
    2. Runs FusionOps triage agent on the result
    3. Returns combined detection + triage output

    Example body:
    {
        "timestamps": [1710000000.0, 1710000060.0],
        "values": [3.12, 2.98],
        "source_label": "prod-server-01"
    }
    """
    if len(payload.timestamps) != len(payload.values):
        raise HTTPException(400, "timestamps and values must be the same length")
    if len(payload.values) < 10:
        raise HTTPException(400, "Need at least 10 data points for reliable detection")

    # Step 1: Call ThreatFade
    raw = await _call_threatfade("/detect/json", {
        "timestamps": payload.timestamps,
        "values": payload.values,
        "source_label": payload.source_label,
    })

    # Step 2: Run triage agent
    triage = run_triage(raw)

    result = {"detection": raw, "triage": triage}
    _log_event(result)
    return result


@app.post("/detect/scenario", response_model=FullAnalysisResult, tags=["Detection"])
async def detect_scenario(request: ScenarioRequest):
    """
    Run a named simulation scenario through the full FusionOps pipeline.
    Perfect for demos — no real traffic data needed.

    Scenarios: c2_quieting | lotl_gradual | gnss_jam | normal_with_fade | mixed
    """
    valid = ["c2_quieting", "lotl_gradual", "gnss_jam", "normal_with_fade", "mixed"]
    if request.scenario not in valid:
        raise HTTPException(400, f"scenario must be one of: {valid}")

    # Step 1: Call ThreatFade
    raw = await _call_threatfade("/detect/scenario", {"scenario": request.scenario})

    # Step 2: Run triage agent
    triage = run_triage(raw)

    result = {"detection": raw, "triage": triage}
    _log_event(result)
    return result


@app.post("/detect/pcap", response_model=FullAnalysisResult, tags=["Detection"])
async def detect_from_pcap(file: UploadFile = File(...)):
    """
    Upload a PCAP or PCAPNG file for full FusionOps analysis.

    Pipeline:
    1. Forwards PCAP to ThreatFade for entropy + z-score detection
    2. Runs triage agent on detection result
    3. Returns combined detection + triage output

    Validated against: Merlin QUIC C2 (490,565 packets, z-score 14.76)
    """
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(400, "File must be .pcap or .pcapng")

    suffix = ".pcapng" if file.filename.endswith(".pcapng") else ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        contents = await file.read()
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        # Step 1: Forward to ThreatFade
        raw = await _call_threatfade_pcap(tmp_path, file.filename)

        # Step 2: Run triage agent
        triage = run_triage(raw)

        result = {"detection": raw, "triage": triage}
        _log_event(result)
        return result

    finally:
        os.unlink(tmp_path)


@app.post("/triage", tags=["Agents"])
async def triage_only(detection: dict):
    """
    Run the triage agent on an existing detection result.
    Useful if you already have a ThreatFade result and just want triage.
    """
    if not detection:
        raise HTTPException(400, "Detection result cannot be empty")

    triage = run_triage(detection)
    return triage


# ── Dev runner ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.fusionops_api:app",
        host="0.0.0.0",
        port=settings.fusionops_port,
        reload=True
    )