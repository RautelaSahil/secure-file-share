from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from db import db_cursor
import os
import re

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_key")


# Username & Password Rules
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


# Login Required Decorator
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


# Index
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# Register
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

        if not is_valid_password(password):
            flash("Invalid password format")
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
            flash("Invalid username or password")
            return redirect(url_for("register"))

    return render_template("register.html")


# Login
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


# Dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))


# Logout
@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# Entry
if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug)
