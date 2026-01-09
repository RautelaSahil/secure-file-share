from flask import (
    Flask, render_template, request,
    redirect, session, url_for,
    flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from functools import wraps
from db import db_cursor
from crypto_utils import encrypt_bytes
import os
import re
import uuid

# =====================================================
# APP SETUP
# =====================================================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_key")

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")

# =====================================================
# USERNAME NORMALIZATION
# =====================================================
USERNAME_REGEX = re.compile(r'^[A-Za-z0-9_]{4,16}$')

def normalize_username(username: str) -> str:
    if len(username) <= 4:
        return username.lower()
    return username[:4].lower() + username[4:]

def is_valid_username(username: str) -> bool:
    return USERNAME_REGEX.match(username) is not None

# =====================================================
# ERROR HANDLERS
# =====================================================
@app.errorhandler(RequestEntityTooLarge)
def file_too_large(_):
    return jsonify({"error": "File too large (max 10MB)"}), 413

# =====================================================
# AUTH HELPERS
# =====================================================
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

def has_file_access(user_id, file_id, cursor):
    cursor.execute(
        "SELECT owner_id FROM files WHERE id = %s",
        (file_id,)
    )
    row = cursor.fetchone()
    if not row:
        return None

    if row["owner_id"] == user_id:
        return "owner"

    cursor.execute(
        """
        SELECT 1 FROM file_shares
        WHERE file_id = %s
          AND shared_with_user_id = %s
          AND (expires_at IS NULL OR expires_at > NOW())
        """,
        (file_id, user_id)
    )
    return "shared" if cursor.fetchone() else None

# =====================================================
# ROOT
# =====================================================
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# =====================================================
# SHARING APIs (DAY 3)
# =====================================================
@app.route("/api/share", methods=["POST"])
@login_required
def share_file():
    data = request.json
    file_id = data.get("file_id")
    target_username = data.get("username")
    expires_at = data.get("expires_at")

    if not file_id or not target_username:
        return jsonify({"error": "Missing required fields"}), 400

    if not is_valid_username(target_username):
        return jsonify({"error": "Invalid username format"}), 400

    target_norm = normalize_username(target_username)

    with db_cursor() as cursor:
        cursor.execute(
            "SELECT owner_id FROM files WHERE id = %s",
            (file_id,)
        )
        row = cursor.fetchone()

        if not row or row["owner_id"] != session["user_id"]:
            return jsonify({"error": "Only owner can share"}), 403

        cursor.execute(
            "SELECT id FROM users WHERE username_normalized = %s",
            (target_norm,)
        )
        target_user = cursor.fetchone()

        if not target_user:
            return jsonify({"error": "Target user not found"}), 404

        try:
            cursor.execute(
                """
                INSERT INTO file_shares (file_id, shared_with_user_id, expires_at)
                VALUES (%s, %s, %s)
                """,
                (file_id, target_user["id"], expires_at)
            )
        except Exception:
            return jsonify({
                "error": "This file is already shared with this user. Uploading a new copy creates a separate shareable file."
            }), 400

    return jsonify({"message": "File shared successfully"})

@app.route("/api/files/shared", methods=["GET"])
@login_required
def shared_files():
    with db_cursor() as cursor:
        cursor.execute(
            """
            SELECT
                f.id,
                f.original_filename,
                u.username AS owner,
                fs.expires_at
            FROM file_shares fs
            JOIN files f ON fs.file_id = f.id
            JOIN users u ON f.owner_id = u.id
            WHERE fs.shared_with_user_id = %s
              AND (fs.expires_at IS NULL OR fs.expires_at > NOW())
            ORDER BY f.uploaded_at DESC
            """,
            (session["user_id"],)
        )
        files = cursor.fetchall()

    return jsonify(files)

# =====================================================
# AUTH ROUTES
# =====================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password or not confirm:
            flash("All fields are required")
            return redirect(url_for("register"))

        if not is_valid_username(username):
            flash("Invalid username format")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match")
            return redirect(url_for("register"))

        username_norm = normalize_username(username)
        password_hash = generate_password_hash(password)

        try:
            with db_cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users (username, username_normalized, password_hash)
                    VALUES (%s, %s, %s)
                    """,
                    (username, username_norm, password_hash)
                )
            flash("Registration successful. Please login.")
            return redirect(url_for("login"))
        except Exception:
            flash("Username already exists or invalid")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        username_norm = normalize_username(username)

        with db_cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, password_hash
                FROM users
                WHERE username_normalized = %s
                """,
                (username_norm,)
            )
            user = cursor.fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password")
        return redirect(url_for("login"))

    return render_template("login.html")

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
    return render_template("dashboard.html", username=session.get("username"))

# =====================================================
# FILE UPLOAD (DAY 2)
# =====================================================
@app.route("/api/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    file_bytes = file.read()
    if not file_bytes:
        return jsonify({"error": "Empty file"}), 400

    encrypted_data = encrypt_bytes(file_bytes)

    stored_filename = f"{uuid.uuid4().hex}.bin"
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    with open(os.path.join(UPLOAD_FOLDER, stored_filename), "wb") as f:
        f.write(encrypted_data)

    with db_cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO files (owner_id, original_filename, stored_filename)
            VALUES (%s, %s, %s)
            """,
            (session["user_id"], secure_filename(file.filename), stored_filename)
        )

    return jsonify({"message": "File uploaded successfully"})

@app.route("/api/files/my", methods=["GET"])
@login_required
def my_files():
    with db_cursor() as cursor:
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

    return jsonify(files)

# =====================================================
# ENTRY POINT
# =====================================================
if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug)
