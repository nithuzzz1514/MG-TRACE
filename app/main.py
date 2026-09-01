"""
main.py
Flask web app: upload an .eml file, see the fraud score / header
forensics / geolocation trace on a dashboard, and download the PDF
forensic report.

Run with:  python -m app.main
Then open: http://127.0.0.1:5000
"""

import os
import tempfile

from flask import Flask, render_template, request, send_file, jsonify

from . import scoring, report_generator

app = Flask(__name__, template_folder="../templates", static_folder="../static")

REPORTS_DIR = os.path.join(tempfile.gettempdir(), "email_forensic_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

_LAST_CASE = {}  # simple in-memory store keyed by case_id, fine for a prototype


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("eml_file")
    if not uploaded or uploaded.filename == "":
        return render_template("index.html", error="Please choose a .eml file to upload.")

    raw_bytes = uploaded.read()
    try:
        case = scoring.build_case(eml_bytes=raw_bytes)
    except Exception as e:
        return render_template("index.html", error=f"Could not parse this file: {e}")

    _LAST_CASE[case["case_id"]] = case
    return render_template("dashboard.html", case=case)


@app.route("/report/<case_id>")
def download_report(case_id):
    case = _LAST_CASE.get(case_id)
    if not case:
        return "Case not found. Please re-analyze the email.", 404

    pdf_path = os.path.join(REPORTS_DIR, f"{case_id}.pdf")
    report_generator.generate_pdf_report(case, pdf_path)
    return send_file(pdf_path, as_attachment=True, download_name=f"forensic_report_{case_id}.pdf")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """JSON API version, useful for testing / integration."""
    uploaded = request.files.get("eml_file")
    if not uploaded:
        return jsonify({"error": "no file provided"}), 400
    raw_bytes = uploaded.read()
    case = scoring.build_case(eml_bytes=raw_bytes)
    _LAST_CASE[case["case_id"]] = case
    # raw_message object isn't JSON serialisable, and isn't part of case anyway
    return jsonify(case)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
