import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.database import Base, SessionLocal, engine
from app.models.scan import Scan
from app.models.user import User
from app.api.scans import router as scans_router
from app.api.auth import router as auth_router
from app.services.security.auth import seed_default_users

# Structured Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("socialshield")

# Metrics state for zero-budget monitoring
_metrics = {
    "start_time": time.time(),
    "total_requests": 0,
    "total_scans": 0,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    Base.metadata.create_all(bind=engine)
    # Seed default user accounts
    with SessionLocal() as db:
        seed_default_users(db)
    logger.info("[STARTUP] Database tables verified and default users seeded.")
    yield


app = FastAPI(
    title="SocialShield API",
    description="Defensive cybersecurity and cyber-fraud intelligence platform",
    version="0.6.0",
    lifespan=lifespan,
)


# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        _metrics["total_requests"] += 1
        start = time.monotonic()
        response: Response = await call_next(request)
        duration_ms = (time.monotonic() - start) * 1000

        # Inject standard security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Log request execution
        if not request.url.path.startswith("/health") and not request.url.path.startswith("/api/metrics"):
            client_ip = request.client.host if request.client else "unknown"
            logger.info(
                f"{request.method} {request.url.path} - {response.status_code} ({duration_ms:.1f}ms) from {client_ip}"
            )

        return response


app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(scans_router)


@app.get("/")
def root():
    return {
        "project": "SocialShield",
        "status": "online",
        "version": "0.6.0",
        "sprint": "Sprint 6: Security Hardening",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "database": "connected",
        "uptime_seconds": int(time.time() - _metrics["start_time"]),
    }


@app.get("/api/metrics")
def get_metrics():
    """Zero-budget operational observability endpoint."""
    with SessionLocal() as db:
        scan_count = db.query(Scan).count()
        user_count = db.query(User).count()

    return {
        "uptime_seconds": int(time.time() - _metrics["start_time"]),
        "total_requests_served": _metrics["total_requests"],
        "total_scans_recorded": scan_count,
        "total_registered_users": user_count,
        "system_status": "operational",
    }