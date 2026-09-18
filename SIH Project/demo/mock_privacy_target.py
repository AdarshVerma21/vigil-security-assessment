"""Local passive data-privacy fixture."""

from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/")
def index():
    return '<a href="/api/export?token=demo-secret-token">export</a>'


@app.get("/api/export")
def export_data():
    return jsonify({
        "email": "alice@example.com",
        "access_token": "eyJdemo.token.value",
        "phone": "+1 555 123 4567",
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5072, debug=False)
