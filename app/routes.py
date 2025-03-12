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
    return render_template('home.html')

@app.route('/group')
def group():
    return render_template('group.html')

@app.route('/mkquiz')
def mkquiz():
    return render_template('mkquiz.html')

@app.route('/notes')
def notes():
    return render_template('notes.html')

@app.route('/login')
def login():
    return render_template('login.html')