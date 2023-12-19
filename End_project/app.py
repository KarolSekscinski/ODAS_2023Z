from flask import Flask, request, render_template



app = Flask(__name__)

@app.route('/')
def all_notes():
    pass


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
    return 'Hello world'
        #user = user_loader(username)
        #if user is None:
        #     return "Nieprawidłowy login lub hasło", 401
        # #if sha256_crypt.verify(password, user.password):
        #     login_user(user)
        #     return redirect('/hello')
        # else:
        #     return "Nieprawidłowy login lub hasło", 401



if __name__ == '__main__':
    app.run(debug=True)
