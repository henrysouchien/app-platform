"""Stable public messages for authentication failures.

Internal exceptions remain in structured logs. Authentication routes expose only
these messages, independent of environment, so development and production share
one client contract.
"""

AUTHENTICATION_FAILED = "Authentication failed"
AUTH_STATUS_UNAVAILABLE = "Authentication status is temporarily unavailable."
AUTH_SERVICE_UNAVAILABLE = (
    "Authentication service is temporarily unavailable. Please retry."
)
SESSION_CLEANUP_FAILED = "Session cleanup failed. Please retry."
