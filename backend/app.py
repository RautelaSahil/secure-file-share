from flask import (
    Flask, render_template, request,
    redirect, session, url_for,
    flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from functools import wraps
from db import get_db_connection
from crypto_utils import encrypt_bytes
import mysql.connector
import os
import uuid

# -------------------------
# App Setup
# -------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_key")

# Max upload size: 10 MB
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")


# -------------------------
# Error Handlers
# -------------------------
@app.errorhandler(RequestEntityTooLarge)
def file_too_large(_):
    return jsonify({"error": "File too large (max 10MB)"}), 413


# -------------------------
# Auth Helper
# -------------------------
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


# -------------------------
# Root Redirect
# -------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# =====================================================
# AUTH ROUTES
# =====================================================

# -------------------------
# Register
# -------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password or not confirm:
            flash("All fields are required")
            return redirect(url_for("register"))

        if len(username) < 3:
            flash("Username must be at least 3 characters")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, password_hash)
            )
            conn.commit()
            flash("Registration successful. Please login.")
            return redirect(url_for("login"))

        except mysql.connector.IntegrityError:
            flash("Username already exists")
            return redirect(url_for("register"))

        except Exception:
            flash("Something went wrong. Try again.")
            return redirect(url_for("register"))

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("register.html")


# -------------------------
# Login
# -------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, password_hash FROM users WHERE username = %s",
            (username,)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password")
        return redirect(url_for("login"))

    return render_template("login.html")


# -------------------------
# Logout
# -------------------------
@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# =====================================================
# DASHBOARD
# =====================================================

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=session.get("username")
    )


# =====================================================
# FILE UPLOAD & OWNERSHIP
# =====================================================

# -------------------------
# Upload File
# -------------------------
@app.route("/api/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    original_filename = secure_filename(file.filename)
    stored_filename = f"{uuid.uuid4().hex}.bin"

    file_bytes = file.read()
    if not file_bytes:
        return jsonify({"error": "Empty file not allowed"}), 400

    encrypted_data = encrypt_bytes(file_bytes)

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    file_path = os.path.join(UPLOAD_FOLDER, stored_filename)

    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO files (owner_id, original_filename, stored_filename)
        VALUES (%s, %s, %s)
        """,
        (session["user_id"], original_filename, stored_filename)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "File uploaded successfully"})


# -------------------------
# Fetch User's Files
# -------------------------
@app.route("/api/files/my", methods=["GET"])
@login_required
def my_files():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT id, original_filename, uploaded_at
        FROM files
        WHERE owner_id = %s
        ORDER BY uploaded_at DESC
        """,
        (session["user_id"],)
    )
    files = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(files)


# =====================================================
# ENTRY POINT
# =====================================================
if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug)
