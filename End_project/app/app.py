import hashlib
import os
import random
import string
import time
from datetime import date
from functools import wraps

# Implementing TOTP
import pyotp
import qrcode
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

from encryption import encrypt, decrypt
from forms import LoginForm, RegisterForm, CreateNoteForm, PasswordForm, TOTPForm

app = Flask(__name__)
app.config['SECRET_KEY'] = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"
ckeditor = CKEditor(app)
Bootstrap5(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
# remote address is the IP address of the user accessing the website.
# default_limits is a list of rules that apply to all routes.

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


# TODO: Create a decorator to monitor system
def monitor_system(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        message = f"{time.ctime()}: Request made by {get_remote_address()}"
        if current_user.is_authenticated:
            print(f"{message}: by {current_user.email}\n")
        else:
            print(f"{message}: by anonymous user. \n")
        return f(*args, **kwargs)
    return decorated_function



@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


def note_author_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        note_id = kwargs['note_id']
        note = db.get_or_404(Note, note_id)
        if note.author != current_user:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# Connect to DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite3.db'
db = SQLAlchemy()
db.init_app(app)


# Configure Tables
class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="notes")
    title = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    encrypted = db.Column(db.Boolean, nullable=False)
    password = db.Column(db.String(250), nullable=True)
    iv = db.Column(db.String(250), nullable=True)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(128))
    salt = db.Column(db.String(100))
    name = db.Column(db.String(100))
    totp_secret = db.Column(db.String(100))
    # This will act like a list of Notes objects attached to each user.
    # The "author" refers to the author property in the Note class
    notes = relationship("Note", back_populates="author")


with app.app_context():
    db.create_all()


# Register new users into the User Table
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5/minute")
@monitor_system
def register():

    form = RegisterForm()
    if form.validate_on_submit():
        # Check if user email is already present in the database.
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        # Hash the password
        salt_and_hash_password = hash_password(form.password.data, salt_length=8).split("$")
        key = pyotp.random_base32()
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=salt_and_hash_password[1],
            salt=salt_and_hash_password[0],
            totp_secret=key
        )

        db.session.add(new_user)
        db.session.commit()

        # Refactor

        # This line will authenticate the user with Flask-login
        # login_user(new_user)
        # return redirect(url_for("get_all_notes"))
        return redirect(url_for("totp", user_id=new_user.id))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/totp', methods=['GET', 'POST'])
@limiter.limit("5/minute")
def totp():
    user_id = request.args.get("user_id")
    # To register a new user, we need to generate a secret key and a QR code
    # This secret key will be used to generate OTPs
    # This QR code will be used to register the OTP with an authenticator app
    # After verifying the OTP, the user will be registered
    form = TOTPForm()
    if form.validate_on_submit():
        user = db.get_or_404(User, user_id)

        if pyotp.TOTP(user.totp_secret).verify(form.token.data):
            login_user(user)
            os.remove("app/static/qr.png")
            return redirect(url_for("get_all_notes"))
        else:
            flash("Incorrect OTP, please try again.")
            return redirect(url_for("totp", user_id=user.id))
    user = db.get_or_404(User, user_id)
    key = user.totp_secret
    uri = pyotp.totp.TOTP(key).provisioning_uri(name=user.name, issuer_name="Secure Notes App")
    qr = qrcode.make(uri).save("app/static/qr.png")

    return render_template("2FA.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute")
@monitor_system
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        # email in db is unique so will only have one result.

        user = result.scalar()

        # User doesn't exist
        if not user:
            flash("User with this credentials doesn't exist, please try again.")
            return redirect(url_for('login'))
        salt = user.salt
        # Password incorrect
        if user.password != hash_password(plaintext=password, init_salt=salt).split("$")[1]:
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            # login_user(user)
            # return redirect(url_for('get_all_notes'))
            return redirect(url_for("totp", user_id=user.id))

    return render_template("login.html", form=form, current_user=current_user)


# All routes below have default rate limits applied to them.
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_notes'))


@app.route('/')
@limiter.limit("30/minute")
def get_all_notes():
    result = db.session.execute(db.select(Note))
    notes = result.scalars().all()
    return render_template("index.html", all_notes=notes, current_user=current_user)


@app.route("/new_note", methods=['GET', 'POST'])
def add_new_note():
    if not current_user.is_authenticated:
        flash("You need to login to access this page.")
        return redirect(url_for('login'))
    
    form = CreateNoteForm()
    if form.validate_on_submit():
        if form.encrypted.data:
            encrypted_note, iv = encrypt(form.body.data, form.password.data)

            new_note = Note(
                title=form.title.data,
                body=encrypted_note,
                author=current_user,
                date=date.today().strftime("%B %d, %Y"),
                encrypted=form.encrypted.data,
                password=form.password.data,
                iv=iv,
            )
        else:
            new_note = Note(
                title=form.title.data,
                body=form.body.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y"),
                encrypted=form.encrypted.data,

            )
        db.session.add(new_note)
        db.session.commit()
        
        return redirect(url_for("get_all_notes"))
    return render_template("make-note.html", form=form, current_user=current_user)


@app.route('/note/<int:note_id>', methods=['GET', 'POST'])
@monitor_system
def show_note(note_id):
    requested_note = db.get_or_404(Note, note_id)
    # Show encrypted note body but add a form to provide password to decrypt
    if requested_note.encrypted:
        form = PasswordForm()
        if form.validate_on_submit():

            if form.password.data == requested_note.password:
                decrypted_note = decrypt(requested_note.body, requested_note.iv, requested_note.password)

                requested_note.body = decrypted_note
                requested_note.encrypted = False

                return render_template("note.html", note=requested_note, current_user=current_user, form=form)
            else:
                flash("Incorrect password, please try again.")
                return redirect(url_for("show_note", note_id=note_id))

    return render_template("note.html", note=requested_note, current_user=current_user)


@app.route('/note/<int:note_id>/edit', methods=['GET', 'POST'])
@note_author_required
def edit_note(note_id):
    note = db.get_or_404(Note, note_id)
    form = CreateNoteForm(
        title=note.title,
        body=note.body,
        encrypted=note.encrypted,
        password=note.password,
    )

    if form.validate_on_submit():
        note.title = form.title.data
        note.body = form.body.data
        db.session.commit()
        return redirect(url_for("show_note", note_id=note.id))
    return render_template("make-note.html", form=form, current_user=current_user)


@app.route('/note/<int:note_id>/delete', methods=['GET', 'POST'])
@note_author_required
def delete_note(note_id):
    note = db.get_or_404(Note, note_id)
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for("get_all_notes"))


def generate_salt(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def hash_password(plaintext, salt_length=0, init_salt="", rounds=500):
    if init_salt == "":
        salt = generate_salt(salt_length)
        init_salt = salt
    else:
        salt = init_salt
    for _ in range(rounds):
        plaintext_with_salt = salt + plaintext
        plaintext_bytes = bytes(plaintext_with_salt, 'ascii')
        sha3 = hashlib.sha3_256(plaintext_bytes).hexdigest()
        salt = sha3
    return init_salt + "$" + salt


if __name__ == '__main__':
    app.run(debug=True, port=5001)
