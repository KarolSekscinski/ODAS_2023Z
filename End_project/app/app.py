import hashlib
import random
import string
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy.orm import relationship
from forms import LoginForm, RegisterForm, CreateNoteForm

SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;':,./<>?`~"

app = Flask(__name__)
app.config['SECRET_KEY'] = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"
ckeditor = CKEditor(app)
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


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


def check_password_strength(password):
    """Check the strength of a password"""
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in SPECIAL_CHARS for char in password):
        return False
    return True


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


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(128))
    salt = db.Column(db.String(100))
    name = db.Column(db.String(100))
    # This will act like a list of Notes objects attached to each user.
    # The "author" refers to the author property in the Note class
    notes = relationship("Note", back_populates="author")


with app.app_context():
    db.create_all()


# Register new users into the User Table
@app.route('/register', methods=['GET', 'POST'])
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
        # if password is too weak
        plaintext_password = form.password.data
        if not check_password_strength(plaintext_password):
            flash("Password is too weak, please try again.")
            return redirect(url_for('register'))
        # Hash the password
        salt_and_hash_password = hash_password(plaintext_password, salt_length=8).split("$")
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=salt_and_hash_password[1],
            salt=salt_and_hash_password[0],
        )
        db.session.add(new_user)
        db.session.commit()
        # This line will authenticate the user with Flask-login
        login_user(new_user)
        return redirect(url_for("get_all_notes"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        # email in db is unique so will only have one result.
        user = result.scalar()
        salt = user.salt
        # Email doesn't exist
        if not user:
            flash("That email doesn't exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif user.password != hash_password(plaintext=password, init_salt=salt).split("$")[1]:
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_notes'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_notes'))


@app.route('/')
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
        new_note = Note(
            title=form.title.data,
            body=form.body.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_note)
        db.session.commit()
        
        return redirect(url_for("get_all_notes"))
    return render_template("make-note.html", form=form, current_user=current_user)


@app.route('/note/<int:note_id>', methods=['GET', 'POST'])
def show_note(note_id):
    requested_note = db.get_or_404(Note, note_id)

    return render_template("note.html", note=requested_note, current_user=current_user)


@app.route('/note/<int:note_id>/edit', methods=['GET', 'POST'])
@note_author_required
def edit_note(note_id):
    note = db.get_or_404(Note, note_id)
    form = CreateNoteForm(
        title=note.title,
        body=note.body
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
