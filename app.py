import csv
import io
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import mysql.connector
from flask import Flask, jsonify, make_response, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "false").lower() == "true"

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["120 per minute"])

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "mfg"),
    "password": os.environ.get("DB_PASSWORD", "change-me"),
    "database": os.environ.get("DB_NAME", "mfg_network_diagnostics"),
}

ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))
TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "0"))


def db():
    return mysql.connector.connect(**DB_CONFIG)


def client_ip():
    # Only trust X-Forwarded-For when the deployment explicitly declares a
    # trusted proxy count. Otherwise request.remote_addr is used.
    if TRUSTED_PROXY_COUNT > 0:
        forwarded = request.headers.get("X-Forwarded-For", "")
        values = [v.strip() for v in forwarded.split(",") if v.strip()]
        if len(values) >= TRUSTED_PROXY_COUNT:
            return values[-TRUSTED_PROXY_COUNT]
    return request.remote_addr or "unknown"


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/diagnostic")
@limiter.limit("20 per minute")
def diagnostic():
    ip = client_ip()
    user_agent = request.headers.get("User-Agent", "")[:1000]
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO ip_logs (ip_address, user_agent, endpoint) VALUES (%s, %s, %s)",
        (ip, user_agent, "/diagnostic"),
    )
    conn.commit()
    cur.close()
    conn.close()
    return render_template("diagnostic.html", recorded=True)


@app.get("/login")
def login():
    if session.get("admin_authenticated"):
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.post("/login")
@limiter.limit("5 per minute")
def login_post():
    password = request.form.get("password", "")
    if not ADMIN_PASSWORD_HASH or not check_password_hash(ADMIN_PASSWORD_HASH, password):
        return render_template("login.html", error="Credenciales incorrectas."), 401
    session.clear()
    session["admin_authenticated"] = True
    return redirect(url_for("dashboard"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/admin")
@admin_required
def dashboard():
    return render_template("dashboard.html")


@app.get("/api/logs")
@admin_required
def api_logs():
    limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
    search = request.args.get("q", "").strip()
    conn = db()
    cur = conn.cursor(dictionary=True)
    if search:
        cur.execute(
            "SELECT id, ip_address, timestamp, user_agent, endpoint FROM ip_logs "
            "WHERE ip_address LIKE %s OR user_agent LIKE %s ORDER BY timestamp DESC LIMIT %s",
            (f"%{search}%", f"%{search}%", limit),
        )
    else:
        cur.execute(
            "SELECT id, ip_address, timestamp, user_agent, endpoint FROM ip_logs "
            "ORDER BY timestamp DESC LIMIT %s",
            (limit,),
        )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.delete("/api/logs/<int:log_id>")
@admin_required
def delete_log(log_id):
    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM ip_logs WHERE id = %s", (log_id,))
    conn.commit()
    deleted = cur.rowcount
    cur.close()
    conn.close()
    return jsonify({"deleted": deleted})


@app.post("/api/logs/purge")
@admin_required
def purge_logs():
    conn = db()
    cur = conn.cursor()
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=RETENTION_DAYS)
    cur.execute("DELETE FROM ip_logs WHERE timestamp < %s", (cutoff,))
    conn.commit()
    deleted = cur.rowcount
    cur.close()
    conn.close()
    return jsonify({"deleted": deleted, "retention_days": RETENTION_DAYS})


@app.get("/api/export.csv")
@admin_required
def export_csv():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, ip_address, timestamp, user_agent, endpoint FROM ip_logs ORDER BY timestamp DESC")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "ip_address", "timestamp", "user_agent", "endpoint"])
    writer.writerows(cur.fetchall())
    cur.close()
    conn.close()
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=ip-logs.csv"
    return response


@app.get("/health")
def health():
    try:
        conn = db()
        conn.close()
        return jsonify({"status": "ok"})
    except Exception:
        return jsonify({"status": "error"}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
