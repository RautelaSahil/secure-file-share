from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from db import db_cursor
import os
import re
import uuid
from werkzeug.utils import secure_filename
from crypto_utils import encrypt_bytes

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_key")

# -------------------------
# Upload Storage Config ✅
# -------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.getenv(
    "UPLOAD_DIR",
    os.path.abspath(os.path.join(BASE_DIR, "..", "storage", "encrypted"))
)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -------------------------
# Username & Password Rules
# -------------------------
USERNAME_REGEX = re.compile(r'^[A-Za-z0-9_]{4,16}$')

def normalize_username(username):
    return username[:4].lower() + username[4:]

def is_valid_username(username):
    return USERNAME_REGEX.match(username) is not None

def is_valid_password(password):
    if len(password) < 6:
        return False
    if not re.search(r'[A-Za-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True

# -------------------------
# Login Required Decorator
# -------------------------
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

# -------------------------
# Index
# -------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# -------------------------
# Register (Auto Login)
# -------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password or not confirm:
            flash("Invalid username or password")
            return redirect(url_for("register"))

        if not is_valid_username(username):
            flash("Invalid username or password")
            return redirect(url_for("register"))

        if not is_valid_password(password):
            flash("Invalid username or password")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Invalid username or password")
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
                user_id = cursor.lastrowid

            session["user_id"] = user_id
            session["username"] = username
            return redirect(url_for("dashboard"))

        except Exception as e:
            print("DB ERROR:", e)
            flash("Invalid username or password")
            return redirect(url_for("register"))

    return render_template("register.html")

# -------------------------
# Login
# -------------------------
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
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password")
        return redirect(url_for("login"))

    return render_template("login.html")

# -------------------------
# Dashboard (Protected)
# -------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))

# -------------------------
# Logout
# -------------------------
@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

# -------------------------
# ✅ Upload (FIXED & COMPLETE)
# -------------------------
@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return {"error": "No file provided"}, 400

    file = request.files["file"]

    if file.filename == "":
        return {"error": "Empty filename"}, 400

    file_bytes = file.read()
    if not file_bytes:
        return {"error": "Empty file"}, 400

    # Encrypt file bytes
    encrypted_data = encrypt_bytes(file_bytes)

    # Secure, server-generated filename
    stored_filename = f"{uuid.uuid4().hex}.bin"
    storage_path = os.path.join(UPLOAD_DIR, stored_filename)

    # Save encrypted file
    with open(storage_path, "wb") as f:
        f.write(encrypted_data)

    # Store metadata
    with db_cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO files (owner_id, original_filename, stored_filename)
            VALUES (%s, %s, %s)
            """,
            (
                session["user_id"],
                secure_filename(file.filename),
                stored_filename
            )
        )

    return {"message": "File uploaded successfully"}, 200

# -------------------------
# Entry
# -------------------------
if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug)
