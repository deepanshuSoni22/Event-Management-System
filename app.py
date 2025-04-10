from flask import Flask, render_template, request, redirect, flash, url_for
from flask_session import Session
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import os
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
Session(app)

login_manager = LoginManager()
login_manager.init_app(app)

# Ensure uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    label = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Interested(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('interested_events', lazy=True))
    event = db.relationship('Event', backref=db.backref('interested_users', lazy=True))

with app.app_context():
    db.create_all()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
def index():
    return render_template("index.html", background_image='/static/images/index-background.jpg')

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html", background_image='/static/images/signup-background.jpg')
    
    email = request.form.get("email")
    password = request.form.get("password")
    confirmation = request.form.get("confirm_password")

    email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    if not email or not re.match(email_pattern, email):
        flash("Invalid or missing email!")
    elif not password:
        flash("Must enter a password!")
    elif not confirmation:
        flash("Must confirm password!")
    elif password != confirmation:
        flash("Passwords do not match!")
    elif User.query.filter_by(email=email).first():
        flash("User already exists. Please log in.")
    else:
        hashed_password = generate_password_hash(password)
        db.session.add(User(email=email, password=hashed_password))
        db.session.commit()
        flash("Signup successful! Please log in.")
        return redirect("/login")
    
    return redirect("/signup")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", background_image='/static/images/login-background.jpg')

    email = request.form.get("email")
    password = request.form.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        flash("Invalid email or password!")
        return redirect("/login")

    login_user(user)
    flash("Login successful!")
    return redirect("/home")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!")
    return redirect("/")

@app.route("/home")
@login_required
def home():
    interested_events = [i.event for i in current_user.interested_events]
    return render_template("home.html", interested_events=interested_events, background_image='/static/images/home-background.jpg')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/host", methods=["GET", "POST"])
@login_required
def host_event():
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        label = request.form.get("label")
        date = request.form.get("date")
        file = request.files.get("image")

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

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
            return redirect(url_for("events"))

    return render_template("host.html", background_image='/static/images/host-background.jpg')

@app.route("/events")
@login_required
def events():
    events = Event.query.all()
    return render_template("events.html", events=events, background_image='/static/images/event-background.jpg')

@app.route("/delete_event/<int:event_id>", methods=["POST"])
@login_required
def delete_event(event_id):
    event = Event.query.get(event_id)
    if event and event.user_id == current_user.id:
        db.session.delete(event)
        db.session.commit()
        flash("Event deleted successfully", "success")
    else:
        flash("You are not authorized to delete this event.", "danger")
    return redirect(url_for('events'))

@app.route("/add_interested/<int:event_id>", methods=["POST"])
@login_required
def add_interested(event_id):
    if not Interested.query.filter_by(user_id=current_user.id, event_id=event_id).first():
        db.session.add(Interested(user_id=current_user.id, event_id=event_id))
        db.session.commit()
        flash("Event added to your interested list.", "success")
    else:
        flash("Already marked interest in this event.", "info")
    return redirect(url_for('events'))

@app.route("/remove_interested/<int:event_id>", methods=["POST"])
@login_required
def remove_interested(event_id):
    entry = Interested.query.filter_by(user_id=current_user.id, event_id=event_id).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()
    return redirect("/home")

if __name__ == "__main__":
    app.run(debug=True)