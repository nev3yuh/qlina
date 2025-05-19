from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))  # removed unique=True
    user_type = db.Column(db.String(20))  # 'cook' or 'guest'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form['name']
    email = request.form['email']
    user_type = request.form['user_type']

    # Check if this user already signed up as the same type
    existing_user = User.query.filter_by(email=email, user_type=user_type).first()
    if existing_user:
        return f"❌ That email is already registered as a {user_type}. Please use a different role or email."

    user = User(name=name, email=email, user_type=user_type)
    db.session.add(user)
    db.session.commit()
    return redirect('/')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
