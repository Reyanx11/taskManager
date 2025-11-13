from dotenv import load_dotenv
import os
import random
from datetime import datetime, timedelta
import requests
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from forms import RegistrationForm, LoginForm, TaskForm, UpdateProfileForm
from models import db, User, Task, Note, generate_confirmation_token, confirm_token

# Load environment variables
load_dotenv()
SENDINBLUE_API_KEY = os.environ.get("SENDINBLUE_API_KEY")


# --- App setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] =os.environ.get('DATABASE_URL')

# --- File upload config ---
ALLOWED_EXTENSIONS = {'pdf'}
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- OTP generation ---
def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(user):
    otp = generate_otp()
    user.otp = otp
    user.otp_created_at = datetime.utcnow()  # Keep UTC-naive
    db.session.commit()

    subject = "Your Task Manager OTP"
    html_content = f"""
    Hi {user.username},<br><br>
    Your OTP to login is: <b>{otp}</b><br>
    This OTP will expire in 5 minutes.
    """
    send_email(user.email, subject, html_content)

# --- Initialize extensions ---
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Sendinblue Email function ---
def send_email(to_email, subject, html_content):
    url = "https://api.sendinblue.com/v3/smtp/email"
    headers = {
        "api-key": SENDINBLUE_API_KEY,
        "Content-Type": "application/json"
    }
    data = {
        "sender": {"name": "Task Manager", "email": "reyankhan7y@gmail.com"},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content
    }
    response = requests.post(url, json=data, headers=headers)
    print(response.status_code, response.text)

# --- Routes ---
@app.route('/')
def home():
    return redirect(url_for('login'))

# --- Registration ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for("login"))

        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user = User(username=form.username.data, email=form.email.data, password=hashed_pw, confirmed=True)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)

# --- Login with OTP ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash("Email not found. Please register.", "danger")
            return redirect(url_for("login"))

        if bcrypt.check_password_hash(user.password, form.password.data):
            send_otp_email(user)
            flash("OTP sent to your email. Please enter it below.", "info")
            return redirect(url_for("verify_otp", email=user.email))
        else:
            flash("Incorrect password. Try again.", "danger")

    return render_template('login.html', form=form)

# --- Verify OTP ---
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = request.args.get("email")
    if request.method == "POST":
        email = request.form.get("email")
        entered_otp = request.form.get("otp")
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Invalid email.", "danger")
            return redirect(url_for("verify_otp"))

        if not user.otp or not user.otp_created_at:
            flash("No OTP found. Please login again.", "warning")
            return redirect(url_for("login"))

        if datetime.utcnow() > user.otp_created_at + timedelta(minutes=5):
            flash("OTP expired. Please login again.", "warning")
            user.otp = None
            user.otp_created_at = None
            db.session.commit()
            return redirect(url_for("login"))

        if entered_otp == user.otp:
            user.otp = None
            user.otp_created_at = None
            db.session.commit()
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect OTP. Try again.", "danger")
            return redirect(url_for("verify_otp", email=email))

    return render_template("verify_otp.html", email=email)

# --- Resend OTP ---
@app.route("/resend-otp/<email>")
def resend_otp(email):
    user = User.query.filter_by(email=email).first_or_404()
    send_otp_email(user)
    flash("OTP resent to your email.", "info")
    return redirect(url_for("verify_otp", email=email))

# --- Dashboard ---
@app.route('/dashboard')
@login_required
def dashboard():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    completed_count = sum(1 for t in tasks if t.completed)
    total_count = len(tasks)
    pending_count = total_count - completed_count
    percent = int((completed_count / total_count) * 100) if total_count > 0 else 0

    return render_template('dashboard.html',
                           total=total_count,
                           completed=completed_count,
                           pending=pending_count,
                           percent=percent)

# --- Profile ---
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.password.data:
            current_user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))
    elif request.method == "GET":
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template("profile.html", form=form)

# --- Tasks ---
@app.route('/tasks', methods=['GET', 'POST'])
@login_required
def tasks():
    tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.due_date.asc()).all()
    if request.method == 'POST':
        due_date = datetime.strptime(request.form.get('due_date'), '%Y-%m-%d') if request.form.get('due_date') else None
        new_task = Task(
            title=request.form.get('title'),
            description=request.form.get('description'),
            due_date=due_date,
            priority=request.form.get('priority'),
            user_id=current_user.id
        )
        db.session.add(new_task)
        db.session.commit()
        flash("Task added successfully!", "success")
        return redirect(url_for('tasks'))
    return render_template('tasks.html', tasks=tasks)

@app.route('/complete/<int:task_id>')
@login_required
def complete(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id == current_user.id:
        task.completed = not task.completed
        db.session.commit()
    return redirect(url_for('tasks'))

@app.route('/delete/<int:task_id>')
@login_required
def delete(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('tasks'))

# --- Notes ---
@app.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    if request.method == 'POST':
        file = request.files.get('pdf')
        filename = secure_filename(file.filename) if file and allowed_file(file.filename) else None
        new_note = Note(
            title=request.form.get('title'),
            content=request.form.get('content'),
            filename=filename,
            user_id=current_user.id,
            created_at=datetime.utcnow()
        )
        if filename:
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        db.session.add(new_note)
        db.session.commit()
        flash("Note added successfully!", "success")
        return redirect(url_for('notes'))

    user_notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.created_at.desc()).all()
    return render_template('notes.html', notes=user_notes)

# --- Password Reset with OTP ---
@app.route("/reset-password-otp", methods=["GET", "POST"])
def reset_password_otp():
    if request.method == "POST":
        email = request.form.get("email")
        entered_otp = request.form.get("otp")
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Invalid email.", "danger")
            return redirect(url_for("reset_password_otp"))

        if not user.otp or not user.otp_created_at or datetime.utcnow() > user.otp_created_at + timedelta(minutes=5):
            flash("OTP expired or not found. Request a new one.", "warning")
            return redirect(url_for("forgot_password"))

        if entered_otp != user.otp:
            flash("Incorrect OTP. Try again.", "danger")
            return redirect(url_for("reset_password_otp"))

        if not new_password:
            flash("Password cannot be empty.", "danger")
            return redirect(url_for("reset_password_otp"))

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("reset_password_otp"))

        user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        user.otp = None
        user.otp_created_at = None
        db.session.commit()

        flash("Password reset successful! You can now log in.", "success")
        return redirect(url_for("login"))

    email = request.args.get("email")
    return render_template("reset_password_otp.html", email=email)

# --- Logout ---
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

# --- Forgot Password ---
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email not found.", "danger")
            return redirect(url_for("forgot_password"))

        send_otp_email(user)
        flash("OTP sent to your email. Enter it below to reset password.", "info")
        return redirect(url_for("reset_password_otp", email=user.email))
    return render_template("forgot_password.html")


if __name__ == "__main__":
    app.run()
