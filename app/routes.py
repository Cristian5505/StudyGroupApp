from flask import Flask, render_template, redirect, url_for, flash, session, request
from app.forms import *
from app.models import *
from app import db
from flask_login import FlaskLoginClient, LoginManager, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import sys
from app import *

@app.route('/')
def home():
    if 'profile_picture' not in session:
        session['profile_picture'] = '/static/profile_pics/scsu.jpg'
    return render_template('home.html')

@app.route('/group')
def group():
    return render_template('group.html')

@app.route('/mkquiz', methods=['GET', 'POST'])
def mkquiz():
    if request.method == 'POST':
        mc_question = request.form.get('mcQuestion')
        mc_options = request.form.get('mcOptions')
        open_ended_question = request.form.get('openEndedQuestion')

        questions = session.get('questions', [])

        if mc_question:
            questions.append({
                'type': 'mc',
                'question': mc_question,
                'options': mc_options.split(',')
            })
        if open_ended_question:
            questions.append({
                'type': 'open_ended',
                'question': open_ended_question
            })

        session['questions'] = questions
        return redirect(url_for('mkquiz'))

    return render_template('mkquiz.html', questions=session.get('questions', []))

@app.route('/clear_session', methods=['POST'])
def clear_session():
    session.pop('questions', None)
    return redirect(url_for('mkquiz'))

@app.route('/notes')
def notes():
    return render_template('notes.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register_handler', methods=['GET', 'POST'])
def register_handler():
    email=request.form.get('email')
    username=request.form.get('username')
    password=request.form.get('password')
    confirm_password=request.form.get('confirm_password')

    if password != confirm_password:
        error_message='Passwords do not match'
        return redirect(url_for('register'))
    
    existing_user=User.query.filter((User.username==username) | (User.email==email)).first()
    if existing_user:
        if existing_user.username==username and existing_user.email==email:
            error_message='Username and Email are in use'
            return redirect(url_for('register',error=error_message))
        elif existing_user.username==username:
            error_message='Username is in use'
            return redirect(url_for('register',error=error_message))
        else:
            error_message='Email is in use'
            return redirect(url_for('register',error=error_message))
        
    hashed_password=generate_password_hash(password)
    new_user=User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    error='Account created, Please Log in'
    return redirect(url_for('login', error_message=error))


@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login_handler', methods=['POST'])
def user_login():
    username=request.form.get('username')
    inputted_password=request.form.get('password')
    user=User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, inputted_password):
        session['logged_in']=True
        session['username']=user.username
        session['Admin']=user.admin
        session['profile_picture'] = user.picture

        return redirect(url_for('home'))
    
    error_message='Incorrect Username or Password'
    return redirect(url_for('login', error=error_message))

@app.route('/customization', methods=['GET', 'POST'])
def customization():
    if request.method == 'POST':
        selected_picture = request.form.get('profile_picture')
        session['profile_picture'] = selected_picture
        if session.get('logged_in'):
            user = User.query.filter_by(username=session['username']).first()
            if user:
                user.picture = selected_picture
                db.session.commit()
        return redirect(url_for('customization'))
    return render_template('customization.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return render_template('login.html')
