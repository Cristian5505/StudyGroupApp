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
        session['profile_picture'] = 'scsu.jpg'
    return render_template('home.html')

@app.route('/group/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group(group_id):
    group = StudyGroup.query.get_or_404(group_id)
    membership = Member.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        flash('You are not a member of this group.')
        return redirect(url_for('home'))

    form = MessageForm()
    if form.validate_on_submit():
        message_text = form.message.data
        new_message = Message(user_id=current_user.id, group_id=group.id, message=message_text)
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent!')
        return redirect(url_for('group', group_id=group.id))

    messages = Message.query.filter_by(group_id=group.id).order_by(Message.time.desc()).all()
    return render_template('group.html', group=group, messages=messages, form=form)

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
        # Use Flask-Login to log the user in
        login_user(user)

        # Flash a success message
        flash('Login successful!')
        return redirect(url_for('home'))

    # Flash an error message if login fails
    flash('Incorrect Username or Password')
    return redirect(url_for('login'))

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

@app.route('/group_management')
@login_required
def group_management():
    owned_groups = StudyGroup.query.filter_by(owner_id=current_user.id).all()
    memberships = Member.query.filter_by(user_id=current_user.id).all()
    member_groups = [membership.group for membership in memberships if membership.group.owner_id != current_user.id]
    return render_template('group_management.html', owned_groups=owned_groups, member_groups=member_groups)

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    form = CreateGroupForm()
    if form.validate_on_submit():
        new_group = StudyGroup(
            name=form.name.data,
            description=form.description.data,
            owner_id=current_user.id,
            public=form.public.data
        )
        db.session.add(new_group)
        db.session.commit()

        new_member = Member(user_id=current_user.id, group_id=new_group.id, moderator=True)
        db.session.add(new_member)
        db.session.commit()

        flash('Group created successfully!')
        return redirect(url_for('group_management'))
    return render_template('create_group.html', form=form)

@app.route('/join_group', methods=['GET', 'POST'])
@login_required
def join_group():
    if request.method == 'POST':
        group_id = request.form.get('group_id')
        group = StudyGroup.query.get(group_id)
        if group and group.public:
            new_member = Member(user_id=current_user.id, group_id=group.id)
            db.session.add(new_member)
            db.session.commit()
            flash('You have joined the group!')
            return redirect(url_for('group_management'))
        else:
            flash('This group is private and cannot be joined without an invitation.')
            return redirect(url_for('join_group'))
    public_groups = StudyGroup.query.filter(
        StudyGroup.public == True,
        ~StudyGroup.members.any(Member.user_id == current_user.id)
    ).all()
    return render_template('join_group.html', public_groups=public_groups)

from flask import redirect, url_for, flash
from app import db
from app.models import *

#Temp route for testing purposes. Delete in final release.
@app.route('/reset_db')
def reset_db():
    db.drop_all()
    db.create_all()
    flash("Database has been reset!")
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))
