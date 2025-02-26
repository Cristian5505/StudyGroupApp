from flask import Flask, render_template, redirect, url_for, flash, session, request
from app.forms import *
from app.models import *
from app import app, db
from flask_login import FlaskLoginClient, LoginManager, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import sys

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = get_user(form.username.data)
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('You have successfully registered')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template('home.html')
    else:
        form = LoginForm()
        return render_template('login.html', form=form)