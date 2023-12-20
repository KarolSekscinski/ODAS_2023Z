import hashlib
import random
import string
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from forms import LoginForm, RegisterForm, CreateNoteForm

app = Flask(__name__)
app.config['SECRET_KEY'] = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"
ckeditor = CKEditor(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# For adding profile images to the notes section
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

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
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(128))
    salt = db.Column(db.String(20))
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

        salt_and_hash_password = hash_password(form.password.data, salt_length=8).split("$")
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




def generate_salt(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def hash_password(plaintext, salt_length=0, init_salt="", rounds=500):
    if init_salt != "":
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