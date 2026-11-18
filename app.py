"""ThreatScope Flask server. Run: python app.py  ->  http://127.0.0.1:5000"""
from flask import Flask, jsonify, request

import analyzer
import intel

app = Flask(__name__, static_folder="static", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.post("/api/analyze")
def analyze():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Send JSON like {\"url\": \"example.com\"}."), 400
    try:
        result = analyzer.analyze(data.get("url"))
    except analyzer.InvalidInput as e:
        return jsonify(error=str(e)), 400
    except Exception:  # never crash on odd input
        app.logger.exception("analysis failed")
        return jsonify(error="Could not analyze this input."), 400
    ti = intel.lookup(result["normalized_url"])
    if ti["status"] == "listed":  # externally verified: override heuristics
        result["score"], result["level"] = max(result["score"], 90), "CRITICAL"
        result["explanation"] += " Score raised to at least 90 because URLhaus (external) lists this URL."
    result["intel"] = ti
    result["recommendations"] = analyzer.recommendations(result, ti)
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
