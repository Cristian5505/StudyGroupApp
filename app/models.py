from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_login import UserMixin, current_user
from app import db, mail
from flask import current_app, url_for, flash
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Message as MailMessage
from app import db

def get_user(username):
    user = User.query.filter_by(username=username).first()
    return user

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True, nullable=False)
    password = db.Column(db.String(256), index=True, nullable=False)
    email = db.Column(db.String(256), index=True, unique=True, nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    admin = db.Column(db.Boolean, index=True, default=False) #site admin, different from group admin / mod
    picture =db.Column(db.String(256), nullable=False, default = "scsu.jpg") #path to their profile picture
    description = db.Column(db.String(256), default = "") #for their profile
    last_active = db.Column(db.DateTime, default=datetime.utcnow) #last time the user was active on the site

    study_groups = db.relationship('StudyGroup', backref='owner', lazy=True) #one to many, user can create multiple study groups
    memberships = db.relationship('Member', backref='user', lazy=True)#one to many, user can be members of multiple groups
    messages = db.relationship('Message', backref='author', lazy=True)#one to many, user can send multiple messages
    
    
    def set_password(self, password):
        self.password = generate_password_hash(password) 

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return '{} {}'.format(self.username, self.email)
    
    def get_owned_groups(self): #Returns all the groups a user is owner of
        return StudyGroup.query.filter_by(owner_id=self.id).all()

    def get_joined_groups(self): #Returns all the groups a user is in.
        return [membership.group for membership in self.memberships]

    def is_moderator(self, group_id): #Checks if a user is a moderator in a given group.
        membership = Member.query.filter_by(user_id=self.id, group_id=group_id).first()
        return membership and membership.moderator
    
    def update_picture(self, newPicture):
        self.picture = newPicture
        db.session.commit()

    def update_description(self, newDescription):
        self.description = newDescription
        db.session.commit()

    def generate_confirmation_token(self):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'confirm': self.id}, salt='email_confirm')
    
    def is_active(self):
        if self.last_active is None:
            return False
        return self.last_active > datetime.now() - timedelta(minutes=5)
    
    @staticmethod
    def confirm_email_token(token, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, salt='email_confirm', max_age=expiration)
        except Exception:
            return None
        return User.query.get(data['confirm'])

    def send_confirmation_email(self):
        token = self.generate_confirmation_token()
        confirm_url = url_for('confirm_email', token=token, _external=True)
        msg = MailMessage(subject='Confirm Your Email', recipients=[self.email])
        msg.body = f'Your confirmation link is: {confirm_url}'
        try:
            mail.send(msg)
            flash(f'Confirmation email sent to{self.email}. Check your inbox!', 'success')
        except Exception as e:
            flash(f'Failed to send confirmation email: {e}', 'error')

class StudyGroup(db.Model):
    __tablename__='studygroup'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True, unique=True, nullable=False)
    description = db.Column(db.Text, index=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    public = db.Column(db.Boolean, default=False) #public or private group
    flairs = db.Column(db.String(256), nullable=True)

    members = db.relationship('Member', backref='group', lazy=True) #one to many, study group can have many members
    messages = db.relationship('Message', backref='group', lazy=True) #one to many, study group can have many messages

    
    def get_members(self): #Returns the list of members in a given group
        return [member.user for member in self.members]

    def has_member(self, user_id): #Checks to see if a user is a member
        return Member.query.filter_by(user_id=user_id, group_id=self.id).first() is not None

    def add_member(self, user_id, moderator=False): #Adds a user as a member, mod is false by default but may be changed to true
        if not self.has_member(user_id):
            new_member = Member(user_id=user_id, group_id=self.id, moderator=moderator)
            db.session.add(new_member)
            db.session.commit()

    def remove_member(self, user_id): #Removes a member
        membership = Member.query.filter_by(user_id=user_id, group_id=self.id).first()
        if membership:
            db.session.delete(membership)
            db.session.commit()
    
    @staticmethod
    def search_by_name(query): #Searches for study groups by the name column, not case sensitive
        return StudyGroup.query.filter(StudyGroup.name.ilike(f"%{query}%")).all()

class Member(db.Model): #many to many, many users can be members of many groups
    __tablename__ = 'member'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('studygroup.id'), index=True, nullable=False)
    moderator = db.Column(db.Boolean, default=False)

class Announcement(db.Model):
    __tablename__ = 'announcement'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('studygroup.id'), index=True, nullable=False)
    text = db.Column(db.Text, nullable=False)
    
    user = db.relationship('User', backref='announcements') #one to many, user can make many announcements
    group = db.relationship('StudyGroup', backref='announcements') #one to many, group can have many announcements

class Note(db.Model):
    __tablename__ = 'note'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('studygroup.id'), index=True, nullable=False)
    file_path = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref='notes') #one to many, user can have multiple notes
    group = db.relationship('StudyGroup', backref='notes') #one to many, group can have multiple notes

class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('studygroup.id'), index=True, nullable=False)
    message = db.Column(db.Text, nullable=False)
    time = db.Column(db.DateTime, default=datetime.now)

class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    questions = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class MutedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('studygroup.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mute_until = db.Column(db.DateTime, nullable=True)  # Optional: Time until mute expires
    
class BannedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('studygroup.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('studygroup.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    uploader = db.relationship('User', backref='uploaded_files')
    group = db.relationship('StudyGroup', backref='uploaded_files')