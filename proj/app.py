from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import bleach
app = Flask(__name__)


def init_db():
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template("form.html")


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
