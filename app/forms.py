from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,TextAreaField, IntegerField, DateField, RadioField, BooleanField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, StopValidation
from wtforms.widgets import CheckboxInput, ListWidget