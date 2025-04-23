from flask import Flask
from sqlalchemy import or_
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from os import environ
import os
from flask_mail import Mail

load_dotenv('.flaskenv')
DB_NAME = environ.get('SQLITE_DB')
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'StudyGroupApp'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://studygroupapp1:csc400group7601@34.122.49.28:5432/StudyGroup'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]= True
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'e.gutowski01@gmail.com'
app.config['MAIL_PASSWORD'] = 'xiou ggxj eqqt dnmp'
app.config['MAIL_DEFAULT_SENDER'] = 'e.gutowski01@gmail.com'

db = SQLAlchemy(app)

#Login Configuration
login = LoginManager(app)
mail = Mail(app)
login.login_view = 'login'

from app import routes, models

@login.user_loader
def load_user(id):
    return models.User.query.get(int(id))
