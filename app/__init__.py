from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from os import environ
import os

load_dotenv('.flaskenv')
DB_NAME = environ.get('SQLITE_DB')
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'StudyGroupApp'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]= True
db = SQLAlchemy(app)

# Login Configuration
login = LoginManager(app)
login.login_view = 'login'

from app import routes, models

@login.user_loader
def load_user(id):
    return models.User.query.get(int(id))

