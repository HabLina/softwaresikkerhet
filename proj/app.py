from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import sqlite3
import bleach
import hashlib
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from flask_oauthlib.client import OAuth
import requests
import pyotp
import qrcode
from io import BytesIO
from flask import send_file
from PIL import Image, ImageDraw
import base64

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", b'\x129)t\x1en\xc3\x0f\x1by\x06O\xba+\xf3\x05\xe9p"\xf9\xc0tN\xb8')  

# Initialize Flask-Limiter for rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"]  # Limit to 5 login attempts per minute
) 

CLIENT_ID = os.environ.get("CLIENT_ID", "YOUR_CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "YOUR_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:8000/callback"
AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
#TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_INFO_URL = "https://api.github.com/user"


oauth = OAuth(app)
github = oauth.remote_app(
    'github',
    consumer_key=os.environ.get("CLIENT_ID", "YOUR_CLIENT_ID"),
    consumer_secret=os.environ.get("CLIENT_SECRET", "YOUR_CLIENT_SECRET"),
    request_token_params={'scope': 'user:email'},
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize'
)


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
            salt BLOB NOT NULL,
            totp_secret TEXT NOT NULL
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
    return 'Welcome to the OAuth2. <a href="/login/oauth">Log in with GitHub</a>'

@app.route("/register", methods=["GET", "POST"])
def registerAccount():
    if request.method == "POST":
        username = bleach.clean(request.form["username"])
        email = bleach.clean(request.form["email"])
        password = bleach.clean(request.form["password"])
        salt = bcrypt.gensalt(rounds=12).decode('utf-8')


        # Hash the password and add salting
        hashedPassword = hash_password(password, salt)

        # Generating a TOTP secret for the user
        totp_secret = pyotp.random_base32()

        try:
            # Insert data into SQLite database
            conn = sqlite3.connect("data.db")
            c = conn.cursor()
            
            # Debug: Print what we are about to insert
            print(f"Trying to insert: {username}, {email}, {hashedPassword}, {salt}, {totp_secret}")
            
            c.execute(
                "INSERT INTO users (username, email, password, salt, totp_secret) VALUES (?, ?, ?, ?, ?)",
                (username, email, hashedPassword, salt, totp_secret),
            )
            conn.commit()

            # Debug: Check if the commit was successful
            print("User successfully added to the database.")
            
        except sqlite3.Error as e:
            # If there's a database error, print it and show an error page
            print(f"Database error: {e}")
            error_message = "An error occurred while registering. Please try again."
            return render_template("error.html", error_message=error_message)
        
        finally:
            # Ensure the connection is closed
            conn.close()

        # If insertion is successful, generate the QR code
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name="MyApp")
        qr = qrcode.make(totp_uri)
        buf = BytesIO()
        qr.save(buf, format="PNG")
        buf.seek(0)
        qr_code_data = base64.b64encode(buf.getvalue()).decode('utf-8')  # Convert to Base64

        # Pass the QR code data to the template
        return render_template("qrcode.html", qr_code_data=qr_code_data)

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = bleach.clean(request.form["username"])
        password = bleach.clean(request.form["password"])
        email = bleach.clean(request.form["email"])
        totp_code = request.form["totp_code"]

        # Connect to the database
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()

        # Get the salt and password that are stored in the db for the chosen user
        cursor.execute("SELECT password, salt, totp_secret FROM users WHERE username = ? OR email = ?", (username, email))
        user = cursor.fetchone()
        conn.close()

        # Check if the user is found
        if not user:
           error_message = "User not found. Are you trying to hack us?"
           return render_template("error.html", error_message=error_message)


        # Check if the password is correct
        if verify_password(password, user[1], user[0]):
            totp = pyotp.TOTP(user[2])  # Use the TOTP secret from the database
            if not totp.verify(totp_code, valid_window=1):
                error_message = "Invalid TOTP code. Are you trying to brute-force us?"
                return render_template("error.html", error_message=error_message)
            return render_template("entries.html")
        
        else:
            error_message = "Invalid password. No XSS attacks here."
            return render_template("error.html", error_message=error_message)

    return render_template("login.html")

@app.route("/login/oauth")
def login_oauth():
    return github.authorize(callback=url_for('github_callback', _external=True))


@app.route("/callback")
def github_callback():
    response = github.authorized_response()
    if response is None or 'access_token' not in response:
        flash("Authorization failed.")
        return redirect(url_for("index"))

    session['github_token'] = (response['access_token'], '')

    # Fetch user details from GitHub
    user_info = github.get('user')
    user_data = user_info.data

    # Store user details securely in the database
    try:
        conn = sqlite3.connect("data.db")
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)",
            (user_data["login"], user_data["email"], "OAuth2_user", "OAuth2_salt")
        )
        conn.commit()
    finally:
        conn.close()

    flash(f"Welcome, {user_data['login']}! You have logged in successfully.")
    return redirect(url_for("index"))

@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')

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
    app.run(host="0.0.0.0", port=8000, debug=True)