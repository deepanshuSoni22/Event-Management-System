from flask import Flask, render_template, request, session, redirect, flash
from flask_session import Session
from flask_login import LoginManager, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
import sqlite3
from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

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
    return render_template("index.html", background_image='/static/index-background.jpg')

# Sign-up route 
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html", background_image='/static/signup-background.jpg')
    
    else:
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirm_password")

        # Validate User's details
        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not email:
            flash("Must provide an email!")
            return redirect("/signup")
        elif not re.match(email_pattern, email):
            flash("Invalid Email format!")
            return redirect("/signup")

        if not password:
            flash("Must enter a password!")
            return redirect("/signup")

        if not confirmation:
            flash("Must provide confirm password!")
            return redirect("/signup")

        if password != confirmation:
            flash("Password and confirm must match!")
            return redirect("/signup")
        
        # Hash the password
        hashed_password = generate_password_hash(password)

        # Check if user already exists
        db = get_db_connection()
        existing_user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if existing_user:
            flash("User already exists. Please log in.")
            db.close() # Ensure database connection is closed
            return redirect("/signup")
        
        # Insert new user into database
        db.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
        db.commit()
        db.close()

        flash("Signup successful! Please log in.")
        return redirect("/login")


# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", background_image='/static/login-background.jpg')

    # Validate user input
    email = request.form.get("email")
    if not email:
        flash("Must provide an email!")
        return redirect("/login")

    password = request.form.get("password")
    if not password:
        flash("Must provide a password!")
        return redirect("/login")

    # Fetch user from database
    db = get_db_connection()
    user_row = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    db.close()

    if user_row is None or not check_password_hash(user_row["password"], password):
        flash("Invalid email or password!")
        return redirect("/login")

    # Successful login
    user = User(id=user_row["id"], email=user_row["email"])  # Create a User instance
    login_user(user)  # Use Flask-Login to log in the user
    flash("Login successful!")
    return redirect("/home")  # Redirect to home after successful login



# Home Route
@app.route("/home")
@login_required
def home():
    return render_template("home.html", background_image='/static/home-background.jpg')


# User loader for flask login
@login_manager.user_loader
def load_user(user_id):
    db = get_db_connection()
    user_row = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()
    
    if user_row is None:
        return None
    
    return User(id=user_row["id"], email=user_row["email"])  # Return a User instance


# Logout route
@app.route("/logout")
@login_required
def logout():
    logout_user()  # Use Flask-Login's logout_user function
    flash("Logged out successfully!")
    return redirect("/")

