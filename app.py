from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import plotly.express as px
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


# ✅ User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


# ✅ Transaction Model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(100))
    description = db.Column(db.String(200))
    amount = db.Column(db.Float)
    category = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


# ✅ Create Tables Automatically
@app.before_first_request
def create_tables():
    db.create_all()


# ✅ Load User Function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ✅ Home/Dashboard Route
@app.route('/')
@login_required
def index():
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    total = sum(t.amount for t in transactions)

    df = pd.DataFrame([{
        'date': t.date,
        'description': t.description,
        'amount': t.amount,
        'category': t.category
    } for t in transactions])

    chart = None
    if not df.empty:
        fig = px.pie(df, names='category', values='amount', title='Spending by Category')
        chart = fig.to_html(full_html=False)

    return render_template('dashboard.html', transactions=transactions, total=total, chart=chart)


# ✅ Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('index'))

    return render_template('register.html')


# ✅ Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html')


# ✅ Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ✅ Add Transaction Route
@app.route('/add', methods=['POST'])
@login_required
def add():
    date = request.form['date']
    description = request.form['description']
    amount = float(request.form['amount'])
    category = request.form['category']

    new_transaction = Transaction(
        date=date,
        description=description,
        amount=amount,
        category=category,
        user_id=current_user.id
    )

    db.session.add(new_transaction)
    db.session.commit()

    return redirect(url_for('index'))


# ✅ Upload CSV Route
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files['file']
    if not file:
        flash('No file selected')
        return redirect(url_for('index'))

    df = pd.read_csv(file)

    for _, row in df.iterrows():
        new_transaction = Transaction(
            date=str(row['date']),
            description=row['description'],
            amount=float(row['amount']),
            category=row['category'],
            user_id=current_user.id
        )
        db.session.add(new_transaction)

    db.session.commit()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)