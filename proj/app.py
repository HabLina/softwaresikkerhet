from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import bleach
import hashlib
import bcrypt
app = Flask(__name__)


def clear_db():
    conn = sqlite3.connect("data.db")
    c = conn.cursor()

    conn.commit()
    conn.close()


def insert_default_data():
    conn = sqlite3.connect("data.db")
    c = conn.cursor()

    # Insert default data (adjust based on your data)
    c.execute("DROP TABLE IF EXISTS entries;")
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            salt BLOB NOT NULL
        )
    """
    )

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

@app.route("/register", methods=["GET","POST"])
def registerAccount():
    if request.method == "POST":
        username = bleach.clean(request.form["username"])
        email = bleach.clean(request.form["email"])
        password = bleach.clean(request.form["password"])
        salt = bcrypt.gensalt(rounds=12).decode('utf-8')

        # Hash the password and add salting
        hashedPassword = hash_password(password, salt)

        # Insert data into SQLite database
        conn = sqlite3.connect("data.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)",
            (username, email, hashedPassword, salt),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("index"))

    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = bleach.clean(request.form["username"])
        email = bleach.clean(request.form["email"])
        password = bleach.clean(request.form["password"])

        # Connect to the database
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()

        # Get the salt and password that are stored in the db for the chosen user
        cursor.execute("SELECT password, salt FROM users WHERE username = ? or email = ?", (username, email))
        user = cursor.fetchone()
        conn.close()

        # Check is the password that is given matches with the password that is in the db
        if verify_password(password, user[1], user[0]):
            return redirect(url_for("index"))
        else:
                print("Invalid password")  # Debugging
    else:
            print("User not found")  # Debugging

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

        # Insert data into SQLite database
        conn = sqlite3.connect("data.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO entries (name, email, message) VALUES (?, ?, ?)",
            (name, email, message),
        )
        conn.commit()
        conn.close()

        return redirect(url_for("index"))


# bleach når vi henter data fra databasen
@app.route("/entries")
def entries():
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("SELECT * FROM entries")
    entries = c.fetchall()
    conn.close()

    sanitized_entries = []
    for entry in entries:
        sanitized_name = bleach.clean(entry[1])  # Sanitizing the name
        sanitized_email = bleach.clean(entry[2], tags=[], attributes={})  # Sanitizing the message
        sanitized_message = bleach.clean(entry[3], tags=[], attributes={})
        sanitized_entries.append((entry[0], sanitized_name, sanitized_email, sanitized_message))  # Appending sanitized data


    return render_template("entries.html", entries=sanitized_entries)

if __name__ == "__main__":
    init_db()
    app.run(port=8000, debug=True)
