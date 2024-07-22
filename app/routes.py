
from flask import render_template, url_for, flash, redirect, request
from app import app, db
from app.models import User
from werkzeug.security import generate_password_hash, check_password_hash

@app.route("/")
@app.route("/home")
def home():
    return render_template('index.html')

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email is already registered. Please use a different email or login.', 'danger')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('thankyou'))
    
    return render_template('signup.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            return redirect(url_for('secret_page'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    
    return render_template('login.html')

@app.route("/secretPage")
def secret_page():
    return render_template('secretPage.html')

@app.route("/thankyou")
def thankyou():
    return render_template('thankyou.html')
