from flask import Flask, render_template, redirect, url_for, flash, session, request, abort
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

    muted_user = MutedUser.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    print(f"Muted user: {muted_user}")  # Debugging
    if muted_user:
        print(f"Muted until: {muted_user.mute_until}")  # Debugging
    
    form = MessageForm()
    if form.validate_on_submit():
        
            # Check if the user is muted
        if muted_user:
            print(f"Muted user exists. Mute until: {muted_user.mute_until}, Current time: {datetime.utcnow()}")
            if muted_user.mute_until is None or muted_user.mute_until > datetime.utcnow():
                print("Mute condition met. Preventing message submission.")
                flash('You are muted and cannot send messages.', 'danger')
            return redirect(url_for('group', group_id=group_id))
        else:
            print("Mute condition not met. Allowing message submission.")

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

    # Fetch messages and uploaded files
    messages = Message.query.filter_by(group_id=group.id).all()
    uploaded_files = UploadedFile.query.filter_by(group_id=group.id).all()

    return render_template('group.html', group=group, messages=messages, uploaded_files=uploaded_files, form=form, muted_user=muted_user)
@app.route('/test_db')
def test_db():
    try:
        result = db.session.execute(text("SELECT VERSION();")).fetchone()
        return f"Database Connected! Version: {result[0]}"
    except Exception as e:
        return f"Database Connection Error: {e}" 
     
@app.route('/mkquiz', methods=['GET', 'POST'])
def mkquiz():
    add_question_form = AddQuestionForm()
    save_quiz_form = SaveQuizForm()
    clear_preview_form = ClearPreviewForm() 

    if request.method == 'POST':
        if add_question_form.add_question.data:
            questions = session.get('questions', [])
            if add_question_form.mcQuestion.data: 
                
                if not add_question_form.mcOptions.data or len(add_question_form.mcOptions.data.split(',')) < 2:
                    flash('Please provide at least two options for your multiple-choice question.', 'error')
                    return redirect(url_for('mkquiz'))
                try:
                    correct_option = int(add_question_form.correctOption.data)
                    if correct_option < 0 or correct_option >= len(add_question_form.mcOptions.data.split(',')):
                        flash('Invalid correct option selected.', 'error')
                        return redirect(url_for('mkquiz'))
                except ValueError:
                    flash('Invalid correct option selected.', 'error')
                    return redirect(url_for('mkquiz'))

                questions.append({
                    'type': 'mc',
                    'question': add_question_form.mcQuestion.data,
                    'options': [option.strip() for option in add_question_form.mcOptions.data.split(',')],
                    'correct': int(add_question_form.correctOption.data) - 1
                })
     
            if add_question_form.openEndedQuestion.data:  
                questions.append({
                    'type': 'open_ended',
                    'question': add_question_form.openEndedQuestion.data
                })
            session['questions'] = questions
            return redirect(url_for('mkquiz')) 

        elif save_quiz_form.save_quiz.data and save_quiz_form.validate():
            return redirect(url_for('save_quiz', quiz_name=save_quiz_form.quizName.data))

        elif clear_preview_form.clear_preview.data: 
            session.pop('questions', None)
            flash('Preview cleared!', 'success')
            return redirect(url_for('mkquiz'))

    return render_template('mkquiz.html', 
                           add_question_form=add_question_form, 
                           save_quiz_form=save_quiz_form,
                           clear_preview_form = clear_preview_form,
                           questions=session.get('questions', []), 
                           enumerate=enumerate)

@app.route('/save_quiz/<quiz_name>', methods=['GET']) 
@login_required
def save_quiz(quiz_name):
    questions = session.get('questions', [])
    if questions:
        new_quiz = Quiz(name=quiz_name, questions=json.dumps(questions), owner_id=current_user.id) 
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
       quizzes = Quiz.query.filter_by(owner_id=current_user.id).all() 
       return render_template('view_quiz.html', quizzes=quizzes)


@app.route('/download_quiz/<int:quiz_id>') 
@login_required
def download_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = json.loads(quiz.questions) 

    downloads_folder = os.path.join(app.root_path, 'downloads')
    os.makedirs(downloads_folder, exist_ok=True)
    file_path = os.path.join(downloads_folder, f'{quiz.name}.txt')
    
    with open(file_path, 'w') as f: 
        f.write(f"Quiz: {quiz.name}\n\n")
        for i, question in enumerate(questions, 1):  
            f.write(f"Question {i}: {question['question']}\n")
            if 'options' in question:
                for j, option in enumerate(question['options']):
                    correct_marker = ' (Correct)' if 'correct' in question and j == question['correct'] else ''
                    f.write(f"- {option}{correct_marker}\n")
            f.write("\n")

    return send_from_directory(downloads_folder, f'{quiz.name}.txt', as_attachment=True)
    
@app.route('/take_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = json.loads(quiz.questions)

    if request.method == 'POST':
        
        user_answers = {}
        for i, question in enumerate(questions):
            if question['type'] == 'mc':
                answer = request.form.get(f'question_{i}')
                try:
                    answer = int(answer)
                except (ValueError, TypeError):
                    answer = None  
                user_answers[i] = answer

       
        all_answered = all(i in user_answers for i, q in enumerate(questions) if q['type'] == 'mc')

        if not all_answered:
            flash('Please answer all multiple-choice questions before submitting.', 'error')
        else:
          
            score = 0
            for i, question in enumerate(questions):
                if question['type'] == 'mc' and user_answers.get(i) == question.get('correct'):
                    score += 1

            return render_template('quiz_results.html', quiz=quiz, questions=questions, user_answers=user_answers,
                                   score=score, enumerate=enumerate)

    return render_template('take_quiz.html', quiz=quiz, questions=questions, enumerate=enumerate)


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
            if not filename.lower().endswith('.txt'):
                filename += '.txt'
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
    form = InviteUserForm()  # Create an instance of the form

    return render_template('profile.html', user=user, groups=groups, form=form)

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
        
        banned_user = BannedUser.query.filter_by(group_id=group_id, user_id=current_user.id).first()

        if banned_user:
            flash('You are banned from this group.', 'danger')
            return redirect(url_for('join_group'))
        
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
    if current_user.id != group.owner_id:
        abort(403)  # Only the group owner can mute users

    duration = int(request.form.get('duration', 0))
    mute_until = datetime.utcnow() + timedelta(minutes=duration)

    muted_user = MutedUser.query.filter_by(group_id=group_id, user_id=user_id).first()
    if muted_user:
        muted_user.mute_until = mute_until  # Update existing mute
    else:
        muted_user = MutedUser(group_id=group_id, user_id=user_id, mute_until=mute_until)
        db.session.add(muted_user)

    db.session.commit()
    flash('User has been muted.', 'success')
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
    if current_user.id != group.owner_id:
        abort(403)  # Only the group owner can ban users

    # Remove the user from the group
    membership = Member.query.filter_by(group_id=group_id, user_id=user_id).first()
    if membership:
        db.session.delete(membership)

    # Add the user to the banned list
    banned_user = BannedUser.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not banned_user:
        banned_user = BannedUser(group_id=group_id, user_id=user_id)
        db.session.add(banned_user)

    db.session.commit()
    flash('User has been banned and removed from the group.', 'success')
    return redirect(url_for('group', group_id=group_id))

#Group File Uploading
@app.route('/upload_file/<int:group_id>', methods=['POST'])
def upload_file(group_id):
    group = StudyGroup.query.get_or_404(group_id)

    # Ensure the user is a member of the group
    membership = Member.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('group', group_id=group_id))


    # Check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part.', 'danger')
        return redirect(url_for('group', group_id=group_id))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file.', 'danger')
        return redirect(url_for('group', group_id=group_id))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Save the file as an uploaded file in the database
        uploaded_file = UploadedFile(
            filename=filename,
            uploader_id=current_user.id,
            group_id=group_id
        )
        db.session.add(uploaded_file)
        db.session.commit()

        flash('File uploaded successfully.', 'success')
        return redirect(url_for('group', group_id=group_id))

@app.route('/invite_user/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
def invite_user(group_id, user_id):
    group = StudyGroup.query.get_or_404(group_id)
    user = User.query.get_or_404(user_id)

    # Ensure the current user is a member of the group
    membership = Member.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        flash('You must be a member of the group to invite others.', 'danger')
        return redirect(url_for('profile', user_id=user_id))

    # Ensure the invited user is not already in the group
    if user in group.members:
        flash('This user is already a member of the group.', 'warning')
        return redirect(url_for('profile', user_id=user_id))

    new_member = Member(user_id=user.id, group_id=group_id)
    db.session.add(new_member)
    db.session.commit()

    flash(f'{user.username} has been invited to the group.', 'success')
    return redirect(url_for('profile', user_id=user_id))

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

@app.before_request
def update_last_active():
    if current_user.is_authenticated:
        current_user.last_active = datetime.now()
        print("User is authenticated, updating last active time.")
        db.session.commit()
