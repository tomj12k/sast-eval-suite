"""Flask app with an OS command injection sink (planted vuln)."""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # VULN: user-controlled host concatenated into a shell command.
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)  # noqa: S602


if __name__ == "__main__":
    app.run()
