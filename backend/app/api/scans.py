import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan
from app.models.user import User
from app.services.osint.coordinator import run_osint_pipeline
from app.services.security.rate_limiter import rate_limit
from app.services.security.rbac import get_current_user, require_role
from app.services.security.ssrf_guard import is_ssrf_safe_url

logger = logging.getLogger("socialshield.scans")
router = APIRouter(prefix="/api/scans", tags=["Scans"])


class ScanCreate(BaseModel):
    target: str = Field(min_length=1, max_length=2048)


class ScanResponse(BaseModel):
    id: int
    target: str
    platform: str
    risk_score: int
    risk_level: str
    findings: list
    evidence: dict = {}
    created_at: object


def serialize_scan(scan: Scan) -> dict:
    findings_raw = scan.findings or "[]"
    parsed_findings = []
    scope_desc = None
    try:
        data = json.loads(findings_raw)
        if isinstance(data, dict):
            parsed_findings = data.get("items", [])
            scope_desc = data.get("analysis_scope")
        elif isinstance(data, list):
            parsed_findings = data
    except Exception:
        parsed_findings = []

    evidence_data = {}
    evidence_raw = getattr(scan, "evidence", None) or "{}"
    try:
        evidence_data = json.loads(evidence_raw) if evidence_raw else {}
    except Exception:
        evidence_data = {}

    findings_list = []
    if scope_desc:
        findings_list.append({
            "type": "analysis_metadata",
            "code": "ANALYSIS_METADATA",
            "severity": "info",
            "description": scope_desc,
            "evidence": scope_desc,
        })
    for f in parsed_findings:
        findings_list.append({
            **f,
            "type": f.get("code", "finding"),
            "description": f.get("evidence", ""),
        })

    return {
        "id": scan.id,
        "target": scan.target,
        "platform": scan.platform,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "findings": findings_list,
        "evidence": evidence_data,
        "created_at": scan.created_at,
    }


@router.post("/", response_model=ScanResponse)
def create_scan(
    scan_data: ScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    _limiter: None = Depends(rate_limit(max_calls=30, window_seconds=60)),
):
    target = scan_data.target.strip()
    client_ip = request.client.host if request.client else "unknown"

    # Sprint 6: SSRF Defense verification
    if "://" in target or ("." in target and "/" in target):
        if not is_ssrf_safe_url(target):
            logger.warning(f"[SECURITY_AUDIT] SSRF attack blocked against target: '{target}' from IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security policy violation: Target resolves to a protected, private, or loopback network address.",
            )

    logger.info(f"[SECURITY_AUDIT] Initiating security scan for: '{target}' from IP: {client_ip}")

    try:
        result = run_osint_pipeline(target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error(f"Scan execution error: {str(exc)}")
        raise HTTPException(status_code=500, detail=f"OSINT assessment error: {str(exc)}")

    findings = list(result["findings"])
    evidence = result.get("evidence", {})

    stored_findings = {
        "input_type": result["input_type"],
        "analysis_scope": result["analysis_scope"],
        "items": findings,
    }

    scan = Scan(
        target=result["target"],
        platform=result["platform"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        findings=json.dumps(stored_findings),
        evidence=json.dumps(evidence),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    logger.info(f"[SECURITY_AUDIT] Scan completed #{scan.id} for: '{target}' - Risk: {scan.risk_level} ({scan.risk_score}/100)")

    return serialize_scan(scan)


@router.get("/", response_model=List[dict])
def list_scans(
    db: Session = Depends(get_db),
    limit: int = Query(default=100, le=500, ge=1),
    offset: int = Query(default=0, ge=0),
    _limiter: None = Depends(rate_limit(max_calls=120, window_seconds=60)),
):
    """Return scan history ordered newest-first."""
    scans = (
        db.query(Scan)
        .order_by(Scan.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [serialize_scan(scan) for scan in scans]


@router.get("/{scan_id}", response_model=dict)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    _limiter: None = Depends(rate_limit(max_calls=120, window_seconds=60)),
):
    """Return a single scan by id."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    return serialize_scan(scan)


@router.get("/{scan_id}/analyst", response_model=dict)
def get_scan_ai_report(
    scan_id: int,
    db: Session = Depends(get_db),
):
    """Return AI Security Analyst report specifically for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    serialized = serialize_scan(scan)
    ai_report = serialized.get("evidence", {}).get("ai_analyst")

    if not ai_report:
        raise HTTPException(status_code=404, detail="AI Security Analyst report not available for this scan.")

    return ai_report


@router.delete("/{scan_id}", response_model=dict)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin"])),
):
    """Admin-only deletion of a scan record."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    db.delete(scan)
    db.commit()
    logger.info(f"[SECURITY_AUDIT] Scan #{scan_id} deleted by Admin '{current_user.username}'")
    return {"status": "deleted", "scan_id": scan_id}