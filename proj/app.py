from flask import Flask, render_template, request, redirect, url_for, flash
import os
import sqlite3
import bleach
import hashlib
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# Initialize Flask-Limiter for rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"]  # Limit to 5 login attempts per minute
) 

CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"
REDIRECT_URI = "http://localhost:8000/callback"
AUTHORIZATION_URL = "https://provider.com/oauth2/authorize"
TOKEN_URL = "https://provider.com/oauth2/token"
USER_INFO_URL = "https://provider.com/userinfo"

MAX_FAILED_ATTEMPTS = 3
TIMEOUT_MINUTES = 5

# Database initialization functions
def clear_db():
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    conn.commit()
    conn.close()

def insert_default_data():
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS entries;")
    c.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            salt BLOB NOT NULL
        )
    """)
    c.execute("INSERT INTO entries (name, email, message) VALUES (?, ?, ?)", ("Lejla", "lejlam@uia.no", "Cowboy-Laila"))
    c.execute("INSERT INTO entries (name, email, message) VALUES (?, ?, ?)", ("Lina", "linaha@uia.no", "Lol"))
    c.execute("INSERT INTO entries (name, email, message) VALUES (?, ?, ?)", ("Julia", "juliamm@uia.no", "McLaren"))
    conn.commit()
    conn.close()

def init_db():
    clear_db()
    insert_default_data()

def hash_password(password, salt):
    combined = (salt + password).encode('utf-8')
    return hashlib.sha256(combined).hexdigest()

# Function to check if password is correct
def verify_password(input_password, stored_salt, stored_hash):
    computed_hash = hash_password(input_password, stored_salt)
    return computed_hash == stored_hash

@app.route("/")
def index():
    return render_template("main.html")

@app.route("/register", methods=["GET","POST"])
def registerAccount():
    if request.method == "POST":
        username = bleach.clean(request.form["username"])
        email = bleach.clean(request.form["email"])
        password = bleach.clean(request.form["password"])
        salt = bcrypt.gensalt(rounds=12).decode('utf-8')


        # Hash the password and add salting
        hashedPassword = hash_password(password, salt)
        try:
            # Insert data into SQLite database
            conn = sqlite3.connect("data.db")
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)",
                (username, email, hashedPassword, salt),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username or email already exists. Please try again.")
            return redirect(url_for("registerAccount"))
        finally:
            conn.close()

        return redirect(url_for("index"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = bleach.clean(request.form["username"])
        password = bleach.clean(request.form["password"])

        # Connect to the database
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()

        # Get the salt and password that are stored in the db for the chosen user
        cursor.execute("SELECT password, salt FROM users WHERE username = ? OR email = ?", (username, username))
        user = cursor.fetchone()
        conn.close()

        # Check if the user is found
        if not user:
            flash("User not found.")
            return render_template("login.html")

        # Check if the password is correct
        if verify_password(password, user[1], user[0]):
            return redirect(url_for("index"))
        else:
            flash("Invalid password.")
            return render_template("login.html")

    return render_template("login.html")

@app.route("/")
def index():
    return render_template("main.html")

@app.route("/submit", methods=["POST"])
def submit():
    if request.method == "POST":
        name = bleach.clean(request.form["name"])
        email = bleach.clean(request.form["email"])
        message = bleach.clean(request.form["message"], tags=[], attributes={})
        try:
            conn = sqlite3.connect("data.db")
            c = conn.cursor()
            c.execute(
                "INSERT INTO entries (name, email, message) VALUES (?, ?, ?)",
                (name, email, message),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("An error occurred while submitting your message. Please try again.")
        finally:
            conn.close()

        return redirect(url_for("index"))

@app.route("/entries")
def entries():
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("SELECT * FROM entries")
    entries = c.fetchall()
    conn.close()

    sanitized_entries = [
        (entry[0], bleach.clean(entry[1]), bleach.clean(entry[2], tags=[], attributes={}), bleach.clean(entry[3], tags=[], attributes={}))
        for entry in entries
    ]
    return render_template("entries.html", entries=sanitized_entries)

if __name__ == "__main__":
    init_db()
    app.run(port=8000, debug=True)