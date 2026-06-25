"""Database access layer."""

import sqlite3

import config


def _connect():
    return sqlite3.connect(config.DATABASE)


def get_user(name):
    """Fetch a user by name.

    [VULN] CWE-89: f-string SQL — name is interpolated directly into the query.
    """
    conn = _connect()
    # [SINK] SQL injection — attacker controls `name`
    query = f"SELECT * FROM users WHERE name = '{name}'"
    row = conn.execute(query).fetchone()
    conn.close()
    return row


def get_user_safe(name):
    """Fetch a user by name using a parameterised query.

    [MITIGATED] CWE-89: parameterised query prevents SQL injection.
    """
    conn = _connect()
    # [SAFE] parameterised query — name is bound, never interpolated
    row = conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()
    conn.close()
    return row


def get_user_by_id(user_id):
    """Fetch a user record by primary key."""
    conn = _connect()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row
