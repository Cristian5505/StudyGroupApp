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
    flairs = SelectMultipleField('Select Flairs', choices=[
            ('Remote', 'Remote'),
            ('In-Person', 'In-Person'),
            ('Note Sharing', 'Note Sharing'),
            ('Quizzes', 'Quizzes'),
            ('Math', 'Math'),
            ('Psychology', 'Psychology'),
            ('Computer Science', 'Computer Science'),
            ('Biology', 'Biology'),
            ('History', 'History'),
            ('Physics', 'Physics')
        ],
        option_widget=CheckboxInput(),
        widget=ListWidget(prefix_label=False)
    )
    
class InviteForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Invite')

class MessageForm(FlaskForm):
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

class UpdateFlairsForm(FlaskForm):
    flairs = SelectMultipleField('Select Flairs', choices=[
        ('Remote', 'Remote'),
        ('In-Person', 'In-Person'),
        ('Note Sharing', 'Note Sharing'),
        ('Quizzes', 'Quizzes'),
        ('Math', 'Math'),
        ('Psychology', 'Psychology'),
        ('Computer Science', 'Computer Science'),
        ('Biology', 'Biology'),
        ('History', 'History'),
        ('Physics', 'Physics')
    ], coerce=str)
    submit = SubmitField('Update Flairs')


class AddQuestionForm(FlaskForm):
    mcQuestion = TextAreaField('Multiple Choice Question')
    mcOptions = StringField('Options (comma-separated)')
    correctOption = IntegerField('Correct Option Index')
    openEndedQuestion = TextAreaField('Open-Ended Question')
    add_question = SubmitField('Add Question')


class SaveQuizForm(FlaskForm):
    quizName = StringField('Quiz Name', validators=[DataRequired()])
    save_quiz = SubmitField('Save Quiz')

class ClearPreviewForm(FlaskForm):
    clear_preview = SubmitField('Clear Preview')
