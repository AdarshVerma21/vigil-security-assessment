"""Local intentionally-insecure API fixture for API scanner demos."""

from flask import Flask, jsonify, request

app = Flask(__name__)
profile = {"id": 1, "name": "demo"}


@app.get("/")
def index():
    return '<a href="/api/profile">profile</a><a href="/graphql">graphql</a>'


@app.post("/login")
def login():
    response = jsonify({"authenticated": True})
    response.set_cookie("sessionid", "demo-api-session")
    return response


@app.route("/api/profile", methods=["GET", "PATCH"])
def api_profile():
    if request.method == "PATCH":
        profile.update(request.get_json(silent=True) or {})
    return jsonify(profile)


@app.post("/graphql")
def graphql():
    query = (request.get_json(silent=True) or {}).get("query", "")
    if "invalidField" in query:
        return "Traceback (most recent call last): /app/api/graphql.py:42", 500
    return jsonify({"data": {"viewer": {"id": 1}}})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5071, debug=False)
