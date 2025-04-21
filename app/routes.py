from flask import Flask, render_template, redirect, url_for, flash, session, request
from sqlalchemy import or_
from app.forms import *
from app.models import *
from app import db
from flask_login import FlaskLoginClient, LoginManager, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sys
from app import *
from sqlalchemy import text 
import json
import os 
from flask import send_from_directory



UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'docx', 'gif', 'mp4', 'mp3'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    profile_picture = 'scsu.jpg'
    if current_user.is_authenticated:
        profile_picture = current_user.picture if current_user.picture else 'scsu.jpg'

    return render_template('home.html', profile_picture=profile_picture, username=current_user.username if current_user.is_authenticated else None)

@app.route('/group/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group(group_id):
    group = StudyGroup.query.get_or_404(group_id)
    membership = Member.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        flash('You are not a member of this group.', 'info')
        return redirect(url_for('home'))

    form = MessageForm()
    if form.validate_on_submit():
        message_text = form.message.data
        new_message = Message(user_id=current_user.id, group_id=group.id, message=message_text)
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent!', 'success')
        return redirect(url_for('group', group_id=group.id))
    
    elif request.form.getlist('flairs'):
        selected_flairs = request.form.getlist('flairs')
        group.flairs = ','.join(selected_flairs)
        db.session.commit()
        return redirect(url_for('group', group_id=group.id))

    messages = Message.query.filter_by(group_id=group.id).order_by(Message.time.desc()).all()
    return render_template('group.html', group=group, messages=messages, form=form)

@app.route('/test_db')
def test_db():
    try:
        result = db.session.execute(text("SELECT VERSION();")).fetchone()
        return f"Database Connected! Version: {result[0]}"
    except Exception as e:
        return f"Database Connection Error: {e}" 
     
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
        if 'action' in request.form: 
               action = request.form['action']
               if action == 'save' and request.form.get('quizName'):
                   return redirect(url_for('save_quiz', quiz_name=request.form.get('quizName')))
               
    return render_template('mkquiz.html', questions=session.get('questions', []))

@app.route('/save_quiz/<quiz_name>', methods=['GET']) 
@login_required
def save_quiz(quiz_name):
    questions = session.get('questions', [])
    if questions:
        new_quiz = Quiz(name=quiz_name, questions=json.dumps(questions), owner_id=current_user.id)  # Set owner_id
        db.session.add(new_quiz)
        db.session.commit()
        session.pop('questions', None) 
        flash('Quiz saved successfully!', 'success')
    else:
        flash('No questions to save!', 'info')
    return redirect(url_for('mkquiz'))

@app.route('/view_quizzes')
@login_required
def view_quizzes():
       quizzes = Quiz.query.filter_by(owner_id=current_user.id).all()  # Filter by owner_id
       return render_template('view_quiz.html', quizzes=quizzes)

@app.route('/download_quiz/<int:quiz_id>') 
@login_required
def download_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = json.loads(quiz.questions) 

    downloads_folder = os.path.join(app.root_path, 'downloads')
    os.makedirs(downloads_folder, exist_ok=True)
    file_path = os.path.join(downloads_folder, f'{quiz.name}.txt')
    
    with open(file_path, 'w') as f:  # Open in write mode ('w')
        f.write(f"Quiz: {quiz.name}\n\n")
        for i, question in enumerate(questions, 1):  # Start numbering from 1
            f.write(f"Question {i}: {question['question']}\n")
            if 'options' in question:
                f.write("Options:\n" + "\n".join([f"- {option}" for option in question['options']]) + "\n")
            f.write("\n")

    return send_from_directory(downloads_folder, f'{quiz.name}.txt', as_attachment=True)
    
@app.route('/clear_session', methods=['POST'])
def clear_session():
    session.pop('questions', None)
    return redirect(url_for('mkquiz'))

@app.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    os.makedirs(user_folder, exist_ok=True)

    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(user_folder, filename))
                flash('File uploaded successfully!', 'success')
                return redirect(url_for('notes'))

        if 'content' in request.form:
            text_content = request.form.get('content')
            filename = secure_filename(request.form.get('filename', 'new_file.txt'))
            with open(os.path.join(user_folder, filename), 'w') as f:
                f.write(text_content)
            flash('Text file created successfully!', 'success')
            return redirect(url_for('notes'))

    files = os.listdir(user_folder)
    return render_template('notes.html', files=files)
    
@app.route('/download_file/<filename>')
@login_required
def download_file(filename):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    return send_from_directory(user_folder, filename, as_attachment=True)

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

    new_user.send_confirmation_email()
    
    flash('Account created! Please check your email to confirm your account.', 'info')
    return redirect(url_for('login'))

@app.route('/confirm_email/<token>')
def confirm_email(token):
    user = User.confirm_email_token(token)
    if not user:
        flash('The confirmation link is invalid or has expired.', 'info')
        return redirect(url_for('login'))
    if user.email_confirmed == True:
        flash('This account has already been confirmed. Please log in.', 'info')
    
    user.email_confirmed = True
    db.session.commit()
    flash('Your email has been confirmed!', 'success')
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login_handler', methods=['POST'])
def user_login():
    username=request.form.get('username')
    inputted_password=request.form.get('password')
    user=User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, inputted_password):
        if user.email_confirmed != True:
            flash('Please confirm email before logging in.', 'warning')
            return redirect(url_for('login'))

        else:
            # Use Flask-Login to log the user in
            login_user(user)

            # Flash a success message
            flash('Login successful!', 'success')
            return redirect(url_for('home'))

    # Flash an error message if login fails
    flash('Incorrect Username or Password', 'warning')
    return redirect(url_for('login'))

@app.route('/customization', methods=['GET', 'POST'])
@login_required
def customization():
    if request.method == 'POST':
        selected_picture = request.form.get('profile_picture')
        new_description = request.form.get('description')

        if selected_picture:
            current_user.picture = selected_picture

        if new_description is not None:
            current_user.description = new_description

        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('customization'))

    return render_template('customization.html')

@app.route('/profile/<int:user_id>') #allows for clicking on someones profile to see their pic, description, and groups
@login_required
def profile(user_id):
    user = User.query.get(user_id)
    groups = StudyGroup.query.join(Member).filter(Member.user_id == user.id).all()
    return render_template('profile.html', user=user, groups=groups)

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
        selected_flairs = ",".join(form.flairs.data)
        new_group = StudyGroup(
            name=form.name.data,
            description=form.description.data,
            owner_id=current_user.id,
            public=form.public.data,
            flairs=selected_flairs
        )
        db.session.add(new_group)
        db.session.commit()

        new_member = Member(user_id=current_user.id, group_id=new_group.id, moderator=True)
        db.session.add(new_member)
        db.session.commit()

        flash('Group created successfully!', 'success')
        return redirect(url_for('group_management'))
    return render_template('create_group.html', form=form)

@app.route('/join_group', methods=['GET', 'POST'])
@login_required
def join_group():
    search_query = request.args.get('search', '').strip()
    #case insensitive search, doesn't show groups user has joined already and flairs and descriptions may be searched
    base_query = StudyGroup.query.filter(
        StudyGroup.public == True,
        ~StudyGroup.members.any(Member.user_id == current_user.id)
    )
    if search_query:
        base_query = base_query.filter(
            or_(
                StudyGroup.name.ilike(f'%{search_query}%'),
                StudyGroup.description.ilike(f'%{search_query}%'),
                StudyGroup.flairs.ilike(f'%{search_query}%')
            )
        )
    public_groups = base_query.all()

    if request.method == 'POST':
        group_id = request.form.get('group_id')
        group = StudyGroup.query.get(group_id)
        if group and group.public:
            new_member = Member(user_id=current_user.id, group_id=group.id)
            db.session.add(new_member)
            db.session.commit()
            flash('You have joined the group!', 'success')
            return redirect(url_for('group_management'))
        else:
            flash('This group is private and cannot be joined without an invitation.', 'info')
            return redirect(url_for('join_group'))
    return render_template('join_group.html', public_groups=public_groups)

#Group Administrative Controls
@app.route('/group/<int:group_id>/mute/<int:user_id>', methods=['POST'])
@login_required
def mute_user(group_id, user_id):
    group = StudyGroup.query.get_or_404(group_id)
    if group.owner_id != current_user.id:
        flash('You do not have permission to mute users.', 'info')
        return redirect(url_for('group', group_id=group_id))

    #mute logic (e.g., store mute duration in the database)
    flash('User has been muted.', 'info')
    return redirect(url_for('group', group_id=group_id))

@app.route('/group/<int:group_id>/kick/<int:user_id>', methods=['POST'])
@login_required
def kick_user(group_id, user_id):
    group = StudyGroup.query.get_or_404(group_id)
    if group.owner_id != current_user.id:
        flash('You do not have permission to kick users.', 'info')
        return redirect(url_for('group', group_id=group_id))

    #Remove the user from the group
    Member.query.filter_by(user_id=user_id, group_id=group_id).delete()
    db.session.commit()
    flash('User has been kicked from the group.', 'info')
    return redirect(url_for('group', group_id=group_id))

@app.route('/group/<int:group_id>/ban/<int:user_id>', methods=['POST'])
@login_required
def ban_user(group_id, user_id):
    group = StudyGroup.query.get_or_404(group_id)
    if group.owner_id != current_user.id:
        flash('You do not have permission to ban users.', 'info')
        return redirect(url_for('group', group_id=group_id))

    #Add the user to a banned list
    flash('User has been banned from the group.', 'info')
    return redirect(url_for('group', group_id=group_id))

#Group File Uploading
@app.route('/group/<int:group_id>/upload', methods=['POST'])
@login_required
def upload_to_group(group_id):
    group = StudyGroup.query.get_or_404(group_id)
    membership = Member.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        flash('You are not a member of this group.', 'info')
        return redirect(url_for('group', group_id=group_id))

    filename = request.form.get('filename')
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    file_path = os.path.join(user_folder, filename)

    if not os.path.exists(file_path):
        flash('File does not exist.', 'info')
        return redirect(url_for('group', group_id=group_id))

    group_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'group_{group_id}')
    os.makedirs(group_folder, exist_ok=True)
    new_file_path = os.path.join(group_folder, filename)
    with open(file_path, 'rb') as src, open(new_file_path, 'wb') as dest:
        dest.write(src.read())
    new_message = Message(
        user_id=current_user.id,
        group_id=group_id,
        message=f"Uploaded file: {filename}",
        file_path=new_file_path
    )
    db.session.add(new_message)
    db.session.commit()

    flash('File uploaded to group successfully!', 'success')
    return redirect(url_for('group', group_id=group_id))

#Temp route for testing purposes. Delete in final release.
@app.route('/reset_db')
def reset_db():
    db.drop_all()
    db.create_all()
    flash("Database has been reset!", 'success')
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))
