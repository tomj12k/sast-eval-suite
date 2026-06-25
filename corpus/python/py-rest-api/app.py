"""Flask REST API entry point."""

import config
import db
import fetch
from auth import require_login
from flask import Flask, jsonify, redirect, request, session

app = Flask(__name__)
app.secret_key = config.SECRET_KEY


@app.route("/login", methods=["POST"])
def login():
    user = db.get_user(request.form["username"])
    if user:
        session["user_id"] = user[0]
        return jsonify({"status": "ok"})
    return jsonify({"error": "not found"}), 404


@app.route("/users/<int:user_id>/profile")
@require_login
def user_profile(user_id):
    """Return a user's profile record.

    [VULN] CWE-639: no ownership check — any authenticated user can fetch
    any other user's profile by supplying an arbitrary user_id in the URL.
    """
    # [SINK] IDOR — user_id from URL, never verified against session["user_id"]
    user = db.get_user_by_id(user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": user[0], "name": user[1], "email": user[2]})


@app.route("/avatar")
@require_login
def avatar():
    """Proxy an avatar image from a caller-supplied URL."""
    url = request.args.get("url", "")
    data = fetch.fetch_avatar(url)
    return data, 200, {"Content-Type": "image/png"}


@app.route("/logout")
def logout():
    """Log out and redirect to /login.

    [FP-DECOY] CWE-601: redirect target is a static literal, not user-controlled.
    A naive scanner may flag redirect() calls without checking the argument.
    """
    session.clear()
    # [FP] static string — not an open redirect
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=config.DEBUG)
