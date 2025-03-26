from flask import redirect, url_for
from werkzeug.security import check_password_hash
from app import db
from models import User

def user_login(username, password):
    user=User.query.filter_by(username==username).first() 
    
    if user and check_password_hash(user.password, password):
        if user.admin:
            return 'Signed in as Admin'
        else:
            return 'Signed in'

    return 'Incorrect Username or Password'


def forgot_password():
    return redirect(url_for('password_reset'))