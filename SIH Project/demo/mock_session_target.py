"""Local intentionally-insecure target for demonstrating session checks.

Run only on localhost:
    python demo/mock_session_target.py
"""

from flask import Flask, jsonify, request


app = Flask(__name__)
DEMO_TOKEN = "demo-session-token"


@app.get("/login")
def login_page():
    response = jsonify({"status": "ready"})
    # Intentionally weak: this pre-auth token is reused after login.
    response.set_cookie("sessionid", DEMO_TOKEN)
    return response


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if not username or not password:
        return jsonify({"error": "credentials required"}), 400
    response = jsonify({"authenticated": True, "user": username})
    # Intentionally insecure: deterministic token and no cookie security flags.
    response.set_cookie("sessionid", DEMO_TOKEN)
    return response


@app.get("/account")
def account():
    if request.cookies.get("sessionid") != DEMO_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"account": "demo", "authenticated": True})


@app.post("/logout")
def logout():
    # Intentionally insecure: logout does not invalidate the server-side token.
    return jsonify({"logged_out": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5070, debug=False)
