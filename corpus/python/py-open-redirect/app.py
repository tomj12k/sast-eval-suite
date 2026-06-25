"""Flask app with open-redirect sinks: real, mitigated, and a false positive."""

from urllib.parse import urlparse

from flask import Flask, redirect, request

app = Flask(__name__)

_ALLOWED = {"app.example.com"}


@app.route("/go")
def go():
    target = request.args.get("next", "")
    # VULN: user-controlled redirect target, no validation -> open redirect.
    return redirect(target)


@app.route("/go-safe")
def go_safe():
    target = request.args.get("next", "")
    # Mitigated: only redirect to an allowlisted host.
    if urlparse(target).hostname in _ALLOWED:
        return redirect(target)
    return redirect("/")


@app.route("/home")
def home():
    # Static literal target, not user-controlled -> false positive for scanners.
    return redirect("/dashboard")
