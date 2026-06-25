"""Flask app with a server-side template injection sink (planted vuln)."""

from flask import Flask, request
from flask import render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # VULN: user input concatenated into a template string -> SSTI.
    return render_template_string("<h1>Hello " + name + "</h1>")
