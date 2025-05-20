import os
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # this redirects unauthorized users

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150))
    user_type = db.Column(db.String(50))
    password_hash = db.Column(db.String(200))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/signup", methods=["POST"])
def signup():
    name = request.form['name']
    email = request.form['email']
    user_type = request.form['user_type']
    password = request.form['password']

    # Check if this user already exists with same email + user_type
    existing_user = User.query.filter_by(email=email, user_type=user_type).first()
    if existing_user:
        return "You already signed up as this role."

    new_user = User(name=name, email=email, user_type=user_type)
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)
    return redirect("/dashboard")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect("/dashboard")
        return "Invalid credentials"
    
    return render_template("login.html")  # We'll make this soon

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.route("/dashboard")
@login_required
def dashboard():
    return f"Welcome {current_user.name} ({current_user.user_type})"


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
