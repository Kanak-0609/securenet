from flask import Flask, request, jsonify
from flask_cors import CORS
from db import get_db
from detection import detect_anomalies
import uuid

app = Flask(__name__)
CORS(app)  # allows your frontend (opened as a file / different origin) to call this API

db = get_db()


@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "traffic_log" not in request.files:
        return jsonify({"error": "No file uploaded. Use form-data key 'traffic_log'."}), 400

    file = request.files["traffic_log"]
    alerts, total_rows = detect_anomalies(file)

    batch_id = str(uuid.uuid4())
    for alert in alerts:
        alert["batch_id"] = batch_id

    if alerts:
        db.alerts.insert_many(alerts)
        # MongoDB adds an '_id' (ObjectId) to each dict in-place after insert.
        # ObjectId isn't JSON serializable, so strip it before returning the response.
        for alert in alerts:
            alert.pop("_id", None)

    # Record this analysis run so total rows analyzed can be tracked persistently
    # in the database, instead of relying on the browser (which forgets on refresh).
    db.runs.insert_one({
        "batch_id": batch_id,
        "rows_analyzed": total_rows,
        "flagged_count": len(alerts)
    })

    return jsonify({
        "batch_id": batch_id,
        "total_rows_analyzed": total_rows,
        "flagged_count": len(alerts),
        "alerts": alerts
    })


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    severity = request.args.get("severity")
    batch_id = request.args.get("batch_id")

    query = {}
    if severity:
        query["severity"] = severity
    if batch_id:
        query["batch_id"] = batch_id

    alerts = list(db.alerts.find(query, {"_id": 0}))
    return jsonify(alerts)


@app.route("/api/alerts/<alert_id>/resolve", methods=["POST"])
def resolve_alert(alert_id):
    result = db.alerts.update_one({"id": alert_id}, {"$set": {"resolved": True}})
    if result.matched_count == 0:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify({"status": "resolved", "id": alert_id})


@app.route("/api/stats", methods=["GET"])
def get_stats():
    batch_id = request.args.get("batch_id")
    if batch_id:
        run = db.runs.find_one({"batch_id": batch_id}, {"rows_analyzed": 1})
        total_rows = run["rows_analyzed"] if run else 0
    else:
        total_rows = sum(r["rows_analyzed"] for r in db.runs.find({}, {"rows_analyzed": 1}))
    return jsonify({"total_rows_analyzed": total_rows})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)