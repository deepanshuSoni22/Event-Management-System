from flask import Flask, render_template, request, session, redirect, flash
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

# Configure application
app = Flask(__name__)



# Configure session to use filesystem (instead of signed cookies)
session["SESSION_PERMANENET"] = False
session["SESSION_TYPE"] = 'filesystem'
Session(app)


# Database connection function
def get_db_connection():
    db = sqlite3.connect('users.db')
    db.row_factory = sqlite3.Row
    return db

# Create users table if it doesn't exist
def init_db():
    with get_db_connection() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )''')

init_db()


# Ensures that the responses from your Flask application are not cached by browsers or proxies
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Home route
@app.route("/")
def index():
    return render_template("index.html")


# Sign-up route 
@app.route("/signup")
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    
    else:
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirm_password")

        # Validate User's details
        if not email:
            flash("Must provide an Email!")
            return redirect("/signup")

        if not password:
            flash("Must enter a passowrd!")
            return redirect("/signup")

        if not confirmation:
            flash("Must provide confirm passowrd!")
            return redirect("/signup")

        if password != confirmation:
            flash("password and confirm_password must be same!")
            return redirect("/signup")
        
        hashed_password = generate_password_hash(password)

        # Check if user already exists
        db = get_db_connection()
        existing_user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if existing_user:
            flash("User already exists. Please log in.")
            return redirect("/signup")
        
        # Insert new user into database
        db.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
        db.commit()
        db.close()

        flash("Signup successful! Please log in.")
        return redirect("/login")


@app.route("/login")
def login():
    return render_template("login.html")