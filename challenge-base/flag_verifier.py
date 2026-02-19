from flask import Flask, request, jsonify
import hmac
import os
import sys

app = Flask(__name__)

flag_path = "/challenge/flag"
if not os.path.exists(flag_path):
    print(f"ERROR: {flag_path} not found", file=sys.stderr)
    sys.exit(1)

with open(flag_path) as f:
    CORRECT_FLAG = f.read().strip()


@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(force=True, silent=True) or {}
    candidate = str(data.get("flag", ""))
    correct = hmac.compare_digest(candidate, CORRECT_FLAG)
    return jsonify({"correct": correct})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
