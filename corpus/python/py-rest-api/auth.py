"""Authentication and access-control helpers."""

from flask import session


def current_user_id():
    """Return the authenticated user's id from the session, or None."""
    return session.get("user_id")


def require_login(f):
    """Decorator: redirect to /login when no session exists."""
    from functools import wraps

    from flask import redirect

    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user_id() is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return wrapper


# [VULN] CWE-639: ownership is never verified here — callers rely on the
# route-level check, which is absent in /users/<id>/profile.
def can_access_profile(requesting_user_id, target_user_id):
    """Return True if requesting_user_id may read target_user_id's profile.

    Intended as the ownership gate, but the /users/<id>/profile route
    never calls this function, leaving IDOR wide open.
    """
    return requesting_user_id == target_user_id
