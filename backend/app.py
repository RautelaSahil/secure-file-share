from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from db import get_db_connection
import mysql.connector
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_key")

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# -------------------------
# Helper: Login Required
# -------------------------
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


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
# Entry
# -------------------------
if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug)
