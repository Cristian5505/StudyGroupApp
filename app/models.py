from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin, current_user
from app import db

def get_user(username):
    user = User.query.filter_by(username=username).first()
    return user

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True, nullable=False)
    password = db.Column(db.String(64), index=True, nullable=False)
    email = db.Column(db.String(64), index=True, unique=True, nullable=False)
    admin = db.Column(db.Boolean, index=True, default=False)