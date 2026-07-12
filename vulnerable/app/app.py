import os
from flask import Flask, jsonify, make_response, send_from_directory

app = Flask(__name__, static_folder="static", static_url_path="/static")


@app.route("/")
def index():
    resp = make_response("""
    <html><body>
    <h1>Security Config Audit Lab</h1>
    <p>Mode: <strong>VULNERABLE</strong></p>
    <ul>
      <li><a href="/health">/health</a></li>
      <li><a href="/debug">/debug</a></li>
      <li><a href="/static/env-demo.txt">/static/env-demo.txt</a></li>
    </ul>
    </body></html>
    """)
    # VULNERABILITY: session cookie set without Secure / HttpOnly / SameSite flags
    resp.set_cookie("session", "demo-session-value")
    return resp


@app.route("/health")
def health():
    return jsonify({"status": "ok", "mode": "vulnerable"})


@app.route("/debug")
def debug():
    return jsonify({
        "mode": "debug",
        "env": {
            "FLASK_ENV": os.environ.get("FLASK_ENV"),
            "FLASK_DEBUG": os.environ.get("FLASK_DEBUG"),
            "DB_HOST": os.environ.get("DB_HOST"),
            "DB_USER": os.environ.get("DB_USER"),
            "DB_NAME": os.environ.get("DB_NAME"),
            "SECRET_KEY": os.environ.get("SECRET_KEY"),
        },
    })


@app.route("/static/env-demo.txt")
def env_demo():
    return send_from_directory("static", "env-demo.txt", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
