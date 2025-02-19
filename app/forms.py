from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,TextAreaField, IntegerField, DateField, RadioField, BooleanField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, StopValidation
from wtforms.widgets import CheckboxInput, ListWidget

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')