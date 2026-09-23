"""
AegisGraph-SOC Application Entrypoint
Serves REST API and modern SOC Web Console.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import os

from backend.app.api.endpoints import router as api_router, soc_state, SimulationRequest, launch_simulation

app = FastAPI(
    title="AegisGraph-SOC Platform",
    description="Next-Generation Graph-Based SIEM/SOAR & MITRE ATT&CK Attack Path Correlator",
    version="1.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Router (both /api and /api/v1 for standard enterprise versioning)
app.include_router(api_router, prefix="/api")
app.include_router(api_router, prefix="/api/v1")

# Mount Static Frontend
frontend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

@app.on_event("startup")
def startup_event():
    print("[AegisGraph-SOC] Initializing Threat Detection & Graph Correlator Engine...")
    print(f"[AegisGraph-SOC] Loaded {len(soc_state.detector.rules)} Sigma Detection Rules.")
    # Initialize with default baseline simulation so analyst has immediate incident to explore
    try:
        launch_simulation(SimulationRequest(scenario="apt29", target_host="SEC-ANALYST-WS01"))
        print("[AegisGraph-SOC] Seeded baseline APT29 adversary simulation.")
    except Exception as e:
        print(f"[AegisGraph-SOC] Seed simulation error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
