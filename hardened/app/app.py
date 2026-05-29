from flask import Flask, jsonify, abort

app = Flask(__name__, static_folder="static", static_url_path="/static")


@app.route("/")
def index():
    return """
    <html><body>
    <h1>Security Config Audit Lab</h1>
    <p>Mode: <strong>HARDENED</strong></p>
    <ul>
      <li><a href="/health">/health</a></li>
    </ul>
    </body></html>
    """


@app.route("/health")
def health():
    return jsonify({"status": "ok", "mode": "hardened"})


@app.route("/debug")
def debug():
    abort(404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
