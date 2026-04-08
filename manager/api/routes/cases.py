"""
CyberNest Manager -- Cases router.

Full case management: CRUD, tasks, observables, comments, attachments,
timeline view, case merge, and PDF export.
"""

from __future__ import annotations

import hashlib
import io
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user, require_role
from manager.config import get_settings
from manager.db.database import get_db
from manager.db.models import (
    Alert,
    AuditLog,
    Case,
    CaseAttachment,
    CaseComment,
    CaseObservable,
    CaseSeverityEnum,
    CaseStatusEnum,
    CaseTask,
    ObservableDataType,
    TaskStatusEnum,
    TLPLevel,
)
from shared.utils.logger import get_logger

logger = get_logger("manager.cases")
settings = get_settings()

router = APIRouter(prefix="/cases", tags=["Cases"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CaseCreateRequest(BaseModel):
    title: str = Field(..., max_length=500)
    description: Optional[str] = None
    severity: str = Field(default="medium")
    tags: list[str] = Field(default_factory=list)
    tlp: str = Field(default="amber")
    assignee_id: Optional[str] = None


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[list[str]] = None
    tlp: Optional[str] = None
    assignee_id: Optional[str] = None


class TaskCreateRequest(BaseModel):
    title: str = Field(..., max_length=500)
    description: Optional[str] = None
    assignee_id: Optional[str] = None
    due_date: Optional[datetime] = None
    order_index: int = Field(default=0)


class TaskUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    assignee_id: Optional[str] = None
    due_date: Optional[datetime] = None


class ObservableCreateRequest(BaseModel):
    data_type: str = Field(..., description="ip, domain, url, hash, email, filename, registry, other")
    value: str = Field(..., min_length=1)
    description: Optional[str] = None
    is_ioc: bool = False
    tlp: str = Field(default="amber")
    tags: list[str] = Field(default_factory=list)


class CommentCreateRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000)


class CaseMergeRequest(BaseModel):
    source_case_ids: list[str] = Field(..., min_length=1, description="UUIDs of cases to merge into this one")


# ---------------------------------------------------------------------------
# Case CRUD
# ---------------------------------------------------------------------------

@router.get("/")
async def list_cases(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    assignee: Optional[str] = None,
    search: Optional[str] = None,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List cases with pagination and filters."""
    query = select(Case)
    count_query = select(func.count(Case.id))
    conditions = []

    if status_filter:
        try:
            conditions.append(Case.status == CaseStatusEnum(status_filter))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")
    if severity:
        try:
            conditions.append(Case.severity == CaseSeverityEnum(severity))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
    if assignee:
        try:
            conditions.append(Case.assignee == uuid.UUID(assignee))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid assignee UUID")
    if search:
        conditions.append(
            Case.title.ilike(f"%{search}%") | Case.description.ilike(f"%{search}%")
        )

    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    query = query.order_by(Case.updated_at.desc())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    cases = result.scalars().all()

    return {
        "items": [_case_to_dict(c) for c in cases],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_case(
    body: CaseCreateRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new case."""
    try:
        sev = CaseSeverityEnum(body.severity)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {body.severity}")
    try:
        tlp = TLPLevel(body.tlp)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid TLP: {body.tlp}")

    assignee_uuid = None
    if body.assignee_id:
        try:
            assignee_uuid = uuid.UUID(body.assignee_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid assignee UUID")

    case_id_str = f"CASE-{uuid.uuid4().hex[:12].upper()}"

    new_case = Case(
        case_id=case_id_str,
        title=body.title,
        description=body.description,
        severity=sev,
        tags=body.tags,
        tlp=tlp,
        assignee=assignee_uuid or current_user.user_id,
    )
    db.add(new_case)
    await db.flush()

    audit = AuditLog(
        user_id=current_user.user_id,
        action="create",
        resource_type="case",
        resource_id=str(new_case.id),
        details={"title": body.title, "severity": body.severity},
    )
    db.add(audit)

    return _case_to_dict(new_case)


@router.get("/{case_uuid}")
async def get_case(
    case_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get case detail with tasks, observables, comments, and attachments."""
    result = await db.execute(
        select(Case)
        .options(
            selectinload(Case.tasks),
            selectinload(Case.observables),
            selectinload(Case.comments).selectinload(CaseComment.user),
            selectinload(Case.attachments),
            selectinload(Case.alerts),
        )
        .where(Case.id == case_uuid)
    )
    case_obj = result.scalar_one_or_none()
    if case_obj is None:
        raise HTTPException(status_code=404, detail="Case not found")

    data = _case_to_dict(case_obj)
    data["tasks"] = [_task_to_dict(t) for t in case_obj.tasks]
    data["observables"] = [_observable_to_dict(o) for o in case_obj.observables]
    data["comments"] = [_comment_to_dict(c) for c in case_obj.comments]
    data["attachments"] = [_attachment_to_dict(a) for a in case_obj.attachments]
    data["alert_count"] = len(case_obj.alerts)
    return data


@router.put("/{case_uuid}")
async def update_case(
    case_uuid: uuid.UUID,
    body: CaseUpdateRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a case."""
    result = await db.execute(select(Case).where(Case.id == case_uuid))
    case_obj = result.scalar_one_or_none()
    if case_obj is None:
        raise HTTPException(status_code=404, detail="Case not found")

    changes = {}
    if body.title is not None:
        case_obj.title = body.title
        changes["title"] = body.title
    if body.description is not None:
        case_obj.description = body.description
        changes["description"] = "updated"
    if body.severity is not None:
        try:
            case_obj.severity = CaseSeverityEnum(body.severity)
            changes["severity"] = body.severity
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {body.severity}")
    if body.status is not None:
        try:
            case_obj.status = CaseStatusEnum(body.status)
            changes["status"] = body.status
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")
    if body.tags is not None:
        case_obj.tags = body.tags
        changes["tags"] = body.tags
    if body.tlp is not None:
        try:
            case_obj.tlp = TLPLevel(body.tlp)
            changes["tlp"] = body.tlp
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid TLP: {body.tlp}")
    if body.assignee_id is not None:
        try:
            case_obj.assignee = uuid.UUID(body.assignee_id)
            changes["assignee"] = body.assignee_id
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid assignee UUID")

    case_obj.updated_at = datetime.now(timezone.utc)
    db.add(case_obj)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="update",
        resource_type="case",
        resource_id=str(case_uuid),
        details=changes,
    )
    db.add(audit)

    return _case_to_dict(case_obj)


@router.delete("/{case_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(
    case_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Delete a case and all related sub-resources."""
    result = await db.execute(select(Case).where(Case.id == case_uuid))
    case_obj = result.scalar_one_or_none()
    if case_obj is None:
        raise HTTPException(status_code=404, detail="Case not found")

    await db.delete(case_obj)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="delete",
        resource_type="case",
        resource_id=str(case_uuid),
        details={"title": case_obj.title},
    )
    db.add(audit)


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

@router.post("/{case_uuid}/tasks", status_code=status.HTTP_201_CREATED)
async def create_task(
    case_uuid: uuid.UUID,
    body: TaskCreateRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a task to a case."""
    result = await db.execute(select(Case).where(Case.id == case_uuid))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Case not found")

    assignee_uuid = None
    if body.assignee_id:
        try:
            assignee_uuid = uuid.UUID(body.assignee_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid assignee UUID")

    task = CaseTask(
        case_id=case_uuid,
        title=body.title,
        description=body.description,
        assignee=assignee_uuid,
        due_date=body.due_date,
        order_index=body.order_index,
    )
    db.add(task)
    await db.flush()
    return _task_to_dict(task)


@router.get("/{case_uuid}/tasks")
async def list_tasks(
    case_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List tasks for a case."""
    result = await db.execute(
        select(CaseTask)
        .where(CaseTask.case_id == case_uuid)
        .order_by(CaseTask.order_index, CaseTask.created_at)
    )
    tasks = result.scalars().all()
    return {"items": [_task_to_dict(t) for t in tasks]}


@router.patch("/{case_uuid}/tasks/{task_uuid}")
async def update_task(
    case_uuid: uuid.UUID,
    task_uuid: uuid.UUID,
    body: TaskUpdateRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a case task."""
    result = await db.execute(
        select(CaseTask).where(
            CaseTask.id == task_uuid, CaseTask.case_id == case_uuid
        )
    )
    task = result.scalar_one_or_none()
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    if body.title is not None:
        task.title = body.title
    if body.description is not None:
        task.description = body.description
    if body.status is not None:
        try:
            task.status = TaskStatusEnum(body.status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")
    if body.assignee_id is not None:
        try:
            task.assignee = uuid.UUID(body.assignee_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid assignee UUID")
    if body.due_date is not None:
        task.due_date = body.due_date

    task.updated_at = datetime.now(timezone.utc)
    db.add(task)
    return _task_to_dict(task)


@router.delete("/{case_uuid}/tasks/{task_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_task(
    case_uuid: uuid.UUID,
    task_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a case task."""
    result = await db.execute(
        select(CaseTask).where(
            CaseTask.id == task_uuid, CaseTask.case_id == case_uuid
        )
    )
    task = result.scalar_one_or_none()
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    await db.delete(task)


# ---------------------------------------------------------------------------
# Observables
# ---------------------------------------------------------------------------

@router.post("/{case_uuid}/observables", status_code=status.HTTP_201_CREATED)
async def create_observable(
    case_uuid: uuid.UUID,
    body: ObservableCreateRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add an observable to a case."""
    result = await db.execute(select(Case).where(Case.id == case_uuid))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        dt = ObservableDataType(body.data_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid data_type: {body.data_type}")
    try:
        tlp = TLPLevel(body.tlp)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid TLP: {body.tlp}")

    obs = CaseObservable(
        case_id=case_uuid,
        data_type=dt,
        value=body.value,
        description=body.description,
        is_ioc=body.is_ioc,
        tlp=tlp,
        tags=body.tags,
        sighted_at=datetime.now(timezone.utc),
    )
    db.add(obs)
    await db.flush()
    return _observable_to_dict(obs)


@router.get("/{case_uuid}/observables")
async def list_observables(
    case_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List observables for a case."""
    result = await db.execute(
        select(CaseObservable)
        .where(CaseObservable.case_id == case_uuid)
        .order_by(CaseObservable.created_at.desc())
    )
    observables = result.scalars().all()
    return {"items": [_observable_to_dict(o) for o in observables]}


@router.delete("/{case_uuid}/observables/{obs_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_observable(
    case_uuid: uuid.UUID,
    obs_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete an observable from a case."""
    result = await db.execute(
        select(CaseObservable).where(
            CaseObservable.id == obs_uuid, CaseObservable.case_id == case_uuid
        )
    )
    obs = result.scalar_one_or_none()
    if obs is None:
        raise HTTPException(status_code=404, detail="Observable not found")
    await db.delete(obs)


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

@router.post("/{case_uuid}/comments", status_code=status.HTTP_201_CREATED)
async def create_comment(
    case_uuid: uuid.UUID,
    body: CommentCreateRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a comment to a case."""
    result = await db.execute(select(Case).where(Case.id == case_uuid))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Case not found")

    comment = CaseComment(
        case_id=case_uuid,
        user_id=current_user.user_id,
        content=body.content,
    )
    db.add(comment)
    await db.flush()
    return {
        "id": str(comment.id),
        "case_id": str(case_uuid),
        "user_id": str(current_user.user_id),
        "username": current_user.username,
        "content": comment.content,
        "created_at": comment.created_at.isoformat() if comment.created_at else None,
    }


@router.get("/{case_uuid}/comments")
async def list_comments(
    case_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List comments for a case."""
    result = await db.execute(
        select(CaseComment)
        .options(selectinload(CaseComment.user))
        .where(CaseComment.case_id == case_uuid)
        .order_by(CaseComment.created_at.asc())
    )
    comments = result.scalars().all()
    return {"items": [_comment_to_dict(c) for c in comments]}


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------

@router.post("/{case_uuid}/attachments", status_code=status.HTTP_201_CREATED)
async def upload_attachment(
    case_uuid: uuid.UUID,
    file: UploadFile = File(...),
    description: Optional[str] = None,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload a file attachment to a case."""
    result = await db.execute(select(Case).where(Case.id == case_uuid))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Case not found")

    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Max size: {settings.MAX_UPLOAD_SIZE} bytes",
        )

    sha256 = hashlib.sha256(content).hexdigest()
    filename = file.filename or "unknown"
    storage_dir = os.path.join(settings.UPLOAD_DIR, str(case_uuid))
    os.makedirs(storage_dir, exist_ok=True)
    storage_path = os.path.join(storage_dir, f"{uuid.uuid4().hex}_{filename}")

    with open(storage_path, "wb") as f:
        f.write(content)

    attachment = CaseAttachment(
        case_id=case_uuid,
        user_id=current_user.user_id,
        filename=filename,
        content_type=file.content_type or "application/octet-stream",
        file_size=len(content),
        storage_path=storage_path,
        sha256_hash=sha256,
        description=description,
    )
    db.add(attachment)
    await db.flush()
    return _attachment_to_dict(attachment)


@router.get("/{case_uuid}/attachments")
async def list_attachments(
    case_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List attachments for a case."""
    result = await db.execute(
        select(CaseAttachment)
        .where(CaseAttachment.case_id == case_uuid)
        .order_by(CaseAttachment.created_at.desc())
    )
    attachments = result.scalars().all()
    return {"items": [_attachment_to_dict(a) for a in attachments]}


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

@router.get("/{case_uuid}/timeline")
async def get_timeline(
    case_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a chronological timeline of all case activity."""
    result = await db.execute(
        select(Case)
        .options(
            selectinload(Case.tasks),
            selectinload(Case.observables),
            selectinload(Case.comments).selectinload(CaseComment.user),
            selectinload(Case.attachments),
            selectinload(Case.alerts),
        )
        .where(Case.id == case_uuid)
    )
    case_obj = result.scalar_one_or_none()
    if case_obj is None:
        raise HTTPException(status_code=404, detail="Case not found")

    timeline = []

    # Case creation
    timeline.append({
        "type": "case_created",
        "timestamp": case_obj.created_at.isoformat(),
        "detail": f"Case '{case_obj.title}' created",
    })

    # Tasks
    for task in case_obj.tasks:
        timeline.append({
            "type": "task_added",
            "timestamp": task.created_at.isoformat(),
            "detail": f"Task: {task.title} (status: {task.status.value})",
            "resource_id": str(task.id),
        })

    # Observables
    for obs in case_obj.observables:
        timeline.append({
            "type": "observable_added",
            "timestamp": obs.created_at.isoformat(),
            "detail": f"Observable: {obs.data_type.value} = {obs.value}",
            "resource_id": str(obs.id),
        })

    # Comments
    for comment in case_obj.comments:
        username = comment.user.username if comment.user else "Unknown"
        timeline.append({
            "type": "comment",
            "timestamp": comment.created_at.isoformat(),
            "detail": comment.content[:200],
            "author": username,
            "resource_id": str(comment.id),
        })

    # Attachments
    for att in case_obj.attachments:
        timeline.append({
            "type": "attachment_uploaded",
            "timestamp": att.created_at.isoformat(),
            "detail": f"File: {att.filename} ({att.file_size} bytes)",
            "resource_id": str(att.id),
        })

    # Linked alerts
    for alert in case_obj.alerts:
        timeline.append({
            "type": "alert_linked",
            "timestamp": alert.created_at.isoformat(),
            "detail": f"Alert: {alert.title} (severity: {alert.severity.value})",
            "resource_id": str(alert.id),
        })

    # Sort by timestamp
    timeline.sort(key=lambda x: x["timestamp"])

    return {"case_id": str(case_uuid), "timeline": timeline}


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

@router.post("/{case_uuid}/merge")
async def merge_cases(
    case_uuid: uuid.UUID,
    body: CaseMergeRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Merge one or more cases into the target case. Moves all sub-resources."""
    # Verify target case exists
    result = await db.execute(select(Case).where(Case.id == case_uuid))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target case not found")

    merged_count = 0
    for src_id_str in body.source_case_ids:
        try:
            src_id = uuid.UUID(src_id_str)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid UUID: {src_id_str}")

        if src_id == case_uuid:
            continue  # Skip self

        src_result = await db.execute(
            select(Case)
            .options(
                selectinload(Case.tasks),
                selectinload(Case.observables),
                selectinload(Case.comments),
                selectinload(Case.attachments),
                selectinload(Case.alerts),
            )
            .where(Case.id == src_id)
        )
        source = src_result.scalar_one_or_none()
        if source is None:
            continue

        # Move tasks
        for task in source.tasks:
            task.case_id = case_uuid
            db.add(task)

        # Move observables
        for obs in source.observables:
            obs.case_id = case_uuid
            db.add(obs)

        # Move comments
        for comment in source.comments:
            comment.case_id = case_uuid
            db.add(comment)

        # Move attachments
        for att in source.attachments:
            att.case_id = case_uuid
            db.add(att)

        # Move alerts
        for alert in source.alerts:
            alert.case_id = case_uuid
            db.add(alert)

        # Add merge note as comment
        merge_comment = CaseComment(
            case_id=case_uuid,
            user_id=current_user.user_id,
            content=f"Merged from case {source.case_id}: {source.title}",
        )
        db.add(merge_comment)

        # Close source case
        source.status = CaseStatusEnum.closed
        source.description = (source.description or "") + f"\n\n[Merged into {target.case_id}]"
        db.add(source)

        merged_count += 1

    audit = AuditLog(
        user_id=current_user.user_id,
        action="merge",
        resource_type="case",
        resource_id=str(case_uuid),
        details={"merged_from": body.source_case_ids, "count": merged_count},
    )
    db.add(audit)

    return {
        "detail": f"Merged {merged_count} case(s) into {target.case_id}",
        "target_case_id": str(case_uuid),
        "merged_count": merged_count,
    }


# ---------------------------------------------------------------------------
# PDF Export
# ---------------------------------------------------------------------------

@router.get("/{case_uuid}/export/pdf")
async def export_case_pdf(
    case_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export case as a PDF report."""
    result = await db.execute(
        select(Case)
        .options(
            selectinload(Case.tasks),
            selectinload(Case.observables),
            selectinload(Case.comments).selectinload(CaseComment.user),
            selectinload(Case.alerts),
        )
        .where(Case.id == case_uuid)
    )
    case_obj = result.scalar_one_or_none()
    if case_obj is None:
        raise HTTPException(status_code=404, detail="Case not found")

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle(
        "CaseTitle", parent=styles["Title"], fontSize=18, spaceAfter=12
    )
    story.append(Paragraph(f"CyberNest Case Report: {case_obj.case_id}", title_style))
    story.append(Spacer(1, 12))

    # Case details
    header_style = ParagraphStyle(
        "SectionHeader", parent=styles["Heading2"], fontSize=14, spaceAfter=6
    )
    story.append(Paragraph("Case Details", header_style))

    case_data = [
        ["Field", "Value"],
        ["Case ID", case_obj.case_id],
        ["Title", case_obj.title],
        ["Severity", case_obj.severity.value],
        ["Status", case_obj.status.value],
        ["TLP", case_obj.tlp.value.upper()],
        ["Created", case_obj.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if case_obj.created_at else "N/A"],
        ["Updated", case_obj.updated_at.strftime("%Y-%m-%d %H:%M:%S UTC") if case_obj.updated_at else "N/A"],
    ]
    table = Table(case_data, colWidths=[2 * inch, 4.5 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), True),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))

    if case_obj.description:
        story.append(Paragraph("Description", header_style))
        story.append(Paragraph(case_obj.description, styles["Normal"]))
        story.append(Spacer(1, 12))

    # Alerts
    if case_obj.alerts:
        story.append(Paragraph(f"Linked Alerts ({len(case_obj.alerts)})", header_style))
        alert_data = [["Alert ID", "Title", "Severity", "Status"]]
        for alert in case_obj.alerts:
            alert_data.append([
                alert.alert_id,
                alert.title[:60],
                alert.severity.value,
                alert.status.value,
            ])
        at = Table(alert_data, colWidths=[1.5 * inch, 2.5 * inch, 1 * inch, 1.5 * inch])
        at.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(at)
        story.append(Spacer(1, 12))

    # Tasks
    if case_obj.tasks:
        story.append(Paragraph(f"Tasks ({len(case_obj.tasks)})", header_style))
        task_data = [["Title", "Status", "Due Date"]]
        for task in case_obj.tasks:
            task_data.append([
                task.title[:60],
                task.status.value,
                task.due_date.strftime("%Y-%m-%d") if task.due_date else "N/A",
            ])
        tt = Table(task_data, colWidths=[3 * inch, 1.5 * inch, 2 * inch])
        tt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(tt)
        story.append(Spacer(1, 12))

    # Observables
    if case_obj.observables:
        story.append(Paragraph(f"Observables ({len(case_obj.observables)})", header_style))
        obs_data = [["Type", "Value", "IOC", "TLP"]]
        for obs in case_obj.observables:
            obs_data.append([
                obs.data_type.value,
                obs.value[:60],
                "Yes" if obs.is_ioc else "No",
                obs.tlp.value.upper(),
            ])
        ot = Table(obs_data, colWidths=[1.5 * inch, 3 * inch, 0.75 * inch, 1.25 * inch])
        ot.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(ot)
        story.append(Spacer(1, 12))

    # Comments
    if case_obj.comments:
        story.append(Paragraph(f"Comments ({len(case_obj.comments)})", header_style))
        for comment in case_obj.comments:
            author = comment.user.username if comment.user else "Unknown"
            ts = comment.created_at.strftime("%Y-%m-%d %H:%M") if comment.created_at else ""
            story.append(Paragraph(
                f"<b>{author}</b> ({ts}): {comment.content}",
                styles["Normal"],
            ))
            story.append(Spacer(1, 6))

    # Footer
    story.append(Spacer(1, 24))
    story.append(Paragraph(
        f"Generated by CyberNest SIEM at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} "
        f"by {current_user.username}",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.grey),
    ))

    doc.build(story)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="case_{case_obj.case_id}.pdf"'
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _case_to_dict(c: Case) -> dict:
    return {
        "id": str(c.id),
        "case_id": c.case_id,
        "title": c.title,
        "description": c.description,
        "severity": c.severity.value,
        "status": c.status.value,
        "assignee": str(c.assignee) if c.assignee else None,
        "tags": c.tags or [],
        "tlp": c.tlp.value,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


def _task_to_dict(t: CaseTask) -> dict:
    return {
        "id": str(t.id),
        "case_id": str(t.case_id),
        "title": t.title,
        "description": t.description,
        "status": t.status.value,
        "assignee": str(t.assignee) if t.assignee else None,
        "due_date": t.due_date.isoformat() if t.due_date else None,
        "order_index": t.order_index,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }


def _observable_to_dict(o: CaseObservable) -> dict:
    return {
        "id": str(o.id),
        "case_id": str(o.case_id),
        "data_type": o.data_type.value,
        "value": o.value,
        "description": o.description,
        "is_ioc": o.is_ioc,
        "tlp": o.tlp.value,
        "tags": o.tags or [],
        "sighted_at": o.sighted_at.isoformat() if o.sighted_at else None,
        "created_at": o.created_at.isoformat() if o.created_at else None,
    }


def _comment_to_dict(c: CaseComment) -> dict:
    return {
        "id": str(c.id),
        "case_id": str(c.case_id),
        "user_id": str(c.user_id),
        "username": c.user.username if c.user else None,
        "content": c.content,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


def _attachment_to_dict(a: CaseAttachment) -> dict:
    return {
        "id": str(a.id),
        "case_id": str(a.case_id),
        "filename": a.filename,
        "content_type": a.content_type,
        "file_size": a.file_size,
        "sha256_hash": a.sha256_hash,
        "description": a.description,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }
