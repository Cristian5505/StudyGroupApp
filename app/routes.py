from flask import Flask, render_template, redirect, url_for, flash, session, request
from app.forms import *
from app.models import *
from app import app, db
from flask_login import FlaskLoginClient, LoginManager, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import sys

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = get_user(form.username.data)
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('You have successfully registered')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

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
        return redirect(url_for('home'))
    return render_template('create_group.html', form=form)

@app.route('/join_group', methods=['GET', 'POST'])
@login_required
def join_group():
    if request.method == 'POST':
        group_id = request.form.get('group_id')
        group = StudyGroup.query.get(group_id)
        if group.public:
            new_member = Member(user_id=current_user.id, group_id=group.id)
            db.session.add(new_member)
            db.session.commit()
            flash('You have joined the group!')
            return redirect(url_for('group', group_id=group.id))
        else:
            flash('This group is private and requires an invitation to join.')
        return redirect(url_for('home'))
    page = request.args.get('page', 1, type=int)
    per_page = 5
    public_groups = StudyGroup.query.filter(
        StudyGroup.public == True,
        ~StudyGroup.members.any(Member.user_id == current_user.id)
        ).all()
    next_url = url_for('join_group', page=page+1) if len(public_groups) == per_page else None
    prev_url = url_for('join_group', page=page-1) if page > 1 else None
    return render_template('join_group.html', public_groups=public_groups)

@app.route('/invite', methods=['GET', 'POST'])
@login_required
def invite():
    group = StudyGroup.query.get(request.args.get('group_id'))
    if group.owner_id != current_user.id:
        flash ('You are not authorized to invite members to this group.')
        return redirect(url_for('home'))
    form = InviteForm()
    if form.validate_on_submit():
        user = get_user(form.username.data)
        if user:
            new_member = Member(user_id=user.id, group_id=group.id)
            db.session.add(new_member)
            db.session.commit()
            flash('Invitation sent!')
        else:
            flash('User not found.')
    return render_template('invite.html', form=form)

@app.route('/my_groups')
@login_required
def my_groups():
    memberships = Member.query.filter_by(user_id=current_user.id).all()
    groups = [membership.group for membership in memberships]
    return render_template('my_groups.html', groups=groups)

@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template('home.html')
    else:
        form = LoginForm()
        return render_template('login.html', form=form)