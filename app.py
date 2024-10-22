from flask import Flask, render_template, request, session, redirect, flash
from flask_session import Session
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import re
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# Configure application
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Ensure this directory exists
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
Session(app)

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(10), nullable=False)  # You might want to use DateTime instead
    label = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create all tables
with app.app_context():
    db.create_all()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Ensure responses aren't cached
@app.after_request
def after_request(response):
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
    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        flash("User already exists. Please log in.")
        return redirect("/signup")
    
    # Insert new user into database
    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash("Signup successful! Please log in.")
    return redirect("/login")

# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", background_image='/static/login-background.jpg')

    email = request.form.get("email")
    if not email:
        flash("Must provide an email!")
        return redirect("/login")

    password = request.form.get("password")
    if not password:
        flash("Must provide a password!")
        return redirect("/login")

    # Fetch user from database
    user_row = User.query.filter_by(email=email).first()

    if user_row is None or not check_password_hash(user_row.password, password):
        flash("Invalid email or password!")
        return redirect("/login")

    # Successful login
    login_user(user_row)
    flash("Login successful!")
    return redirect("/home")

# Home Route
@app.route("/home")
@login_required
def home():
    return render_template("home.html", background_image='/static/home-background.jpg')

# User loader for flask login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Logout route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!")
    return redirect("/")

# Host event route
@app.route("/host", methods=["GET", "POST"])
@login_required
def host_event():
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        label = request.form.get("label")
        date = request.form.get("date")
        file = request.files.get("image")

        # Save the image
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Create new event
            new_event = Event(
                title=title,
                description=description,
                image=filename,
                date=date,
                label=label,
                user_id=current_user.id
            )

            db.session.add(new_event)
            db.session.commit()
            flash("Event added successfully", "success")

    events = Event.query.all()  # Fetch all events to display
    return render_template("host.html", background_image='/static/host-background.jpg', events=events)

if __name__ == "__main__":
    app.run(debug=True)
