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
    
class CreateGroupForm(FlaskForm):
    name = StringField('Group Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    public = BooleanField('Public Group')
    submit = SubmitField('Create Group')
    
class InviteForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Invite')

class MessageForm(FlaskForm):
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')