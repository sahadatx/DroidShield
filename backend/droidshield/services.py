"""Backward-compatible facade for DroidShield domain services.

Service functions flush changes and append audit records inside the supplied
Session. The request or worker owns the surrounding commit/rollback boundary.
"""

from droidshield.access_services import (
    create_workspace_user,
    revoke_workspace_user_sessions,
    update_workspace_user,
    user_query,
    workspace_user,
)
from droidshield.assessment_services import (
    cancel_assessment,
    create_assessment,
    create_authorization,
    is_excluded,
    queue_assessment,
    revoke_authorization,
    submit_assessment,
    update_assessment,
    verify_authorization,
)
from droidshield.auth import utc
from droidshield.directory_services import (
    create_client,
    create_project,
    grant_project,
    update_client,
    update_project,
)
from droidshield.errors import DomainError, conflict, not_found
from droidshield.models import (
    AnalysisJob,
    AppArtifact,
    Assessment,
    AuditEvent,
    Authorization,
    Client,
    IdempotencyRecord,
    Project,
    ProjectAccess,
    User,
)
from droidshield.service_context import (
    Context,
    assessment,
    audit,
    authorization,
    check_revision,
    client,
    client_query,
    paginate,
    project,
    require_admin,
    require_writer,
    visible_projects,
)
from droidshield.service_transactions import once
from droidshield.settings_services import get_workspace_settings, update_workspace_settings

__all__ = [
    "AnalysisJob",
    "AppArtifact",
    "Assessment",
    "AuditEvent",
    "Authorization",
    "Client",
    "Context",
    "DomainError",
    "IdempotencyRecord",
    "Project",
    "ProjectAccess",
    "User",
    "assessment",
    "audit",
    "authorization",
    "cancel_assessment",
    "create_workspace_user",
    "check_revision",
    "client",
    "client_query",
    "conflict",
    "create_assessment",
    "create_authorization",
    "create_client",
    "create_project",
    "grant_project",
    "get_workspace_settings",
    "is_excluded",
    "not_found",
    "once",
    "paginate",
    "project",
    "queue_assessment",
    "require_admin",
    "require_writer",
    "revoke_authorization",
    "revoke_workspace_user_sessions",
    "submit_assessment",
    "update_assessment",
    "update_client",
    "update_project",
    "update_workspace_settings",
    "update_workspace_user",
    "user_query",
    "utc",
    "verify_authorization",
    "workspace_user",
    "visible_projects",
]
