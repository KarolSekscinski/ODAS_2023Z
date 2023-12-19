from flask import Flask, request, render_template
import sqlite3
import hashlib
import random
import string
import markdown
import bleach

app = Flask(__name__)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

DATABASE = "./sqlite3.db"


def generate_salt(length):
    """Function to generate random salt for hash function

    Parameters:
    length (int): Length of salt

    Returns:
    salt (string): Random salt
    """
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def hash_password(plaintext, init_salt="", rounds=500):
    """Function to generate hash value using sha3 - algorithm

    Parameters:
    plaintext (string): Password in plain text
    salt (string): Salt for hash
    rounds (int): Salt rounds performed to hash

    Returns:
    salt$hash (string)

    If salt is empty string then it will generate random salt
    """
    if init_salt == "":
        salt = generate_salt(8)
        init_salt = salt
    else:
        salt = init_salt
    for _ in range(rounds):
        plaintext_with_salt = salt + plaintext
        plaintext_bytes = bytes(plaintext_with_salt, 'ascii')
        sha3 = hashlib.sha3_256(plaintext_bytes).hexdigest()
        salt = sha3
    return init_salt + "$" + salt


@app.route('/', methods=['GET'])
def notes():
    return render_template("notes.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        pass

@app.route("/login", methods=["GET", "POST"])
def login():
    pass


if __name__ == '__main__':
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute("CREATE TABLE user (username VARCHAR(32), password VARCHAR(128), salt VARCHAR(10));")
    sql.execute("DELETE FROM user;")

    sql.execute(
        "INSERT INTO user (username, password) VALUES ('bach', );")
    sql.execute(
        "INSERT INTO user (username, password) VALUES ('john', '$5$rounds=535000$AO6WA6YC49CefLFE$dsxygCJDnLn5QNH/V8OBr1/aEjj22ls5zel8gUh4fw9');")
    sql.execute(
        "INSERT INTO user (username, password) VALUES ('bob', '$5$rounds=535000$.ROSR8G85oGIbzaj$u653w8l1TjlIj4nQkkt3sMYRF7NAhUJ/ZMTdSPyH737');")

    sql.execute("DROP TABLE IF EXISTS notes;")
    sql.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), note VARCHAR(256));")
    sql.execute("DELETE FROM notes;")
    sql.execute("INSERT INTO notes (username, note, id) VALUES ('bob', 'To jest sekret!', 1);")
    db.commit()

    app.run(debug=True)
