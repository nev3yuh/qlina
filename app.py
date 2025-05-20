import os
from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev')  # Needed for session cookies

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=False, nullable=False)
    user_type = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class Meal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    cook_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form['name']
    email = request.form['email']
    user_type = request.form['user_type']
    password = request.form['password']

    existing_user = User.query.filter_by(email=email, user_type=user_type).first()
    if existing_user:
        return "You already signed up as this role."

    new_user = User(name=name, email=email, user_type=user_type)
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)
    return redirect(f"/{user_type}_dashboard")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(f"/{user.user_type}_dashboard")
        return "Invalid credentials"
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/cook_dashboard')
@login_required
def cook_dashboard():
    return render_template("cook_dashboard.html", current_user=current_user)

@app.route('/guest_dashboard')
@login_required
def guest_dashboard():
    return render_template("guest_dashboard.html", current_user=current_user)

@app.route('/dashboard')
@login_required
def dashboard():
    return redirect(f"/{current_user.user_type}_dashboard")

@app.route("/init-db")
def init_db():
    db.create_all()
    return "✅ PostgreSQL tables created!"

@app.route('/post_meal', methods=['GET', 'POST'])
@login_required
def post_meal():
    if current_user.user_type != 'cook':
        return "Unauthorized"

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        meal = Meal(title=title, description=description, cook_id=current_user.id)
        db.session.add(meal)
        db.session.commit()
        return redirect('/cook_dashboard')
    
    return render_template('post_meal.html')

@app.route('/meals')
@login_required
def meals():
    if current_user.user_type != 'guest':
        return "Unauthorized"

    meal_list = Meal.query.all()
    return render_template('meals.html', meals=meal_list)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
