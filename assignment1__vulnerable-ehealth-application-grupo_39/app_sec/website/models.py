from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    appointment = db.relationship('Appointment')
    public_key = db.relationship('PublicKey')
    private_key = db.Column(db.String())
    role = db.Column(db.String(150))
    exam = db.relationship('Exam')


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String())
    date = db.Column(db.String())
    description = db.Column(db.String())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class PublicKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_email = db.Column(db.String())
    to_email = db.Column(db.String())
    message = db.Column(db.String())






class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.Integer, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    description = db.Column(db.String())