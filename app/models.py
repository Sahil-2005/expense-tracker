from . import db
from flask_login import UserMixin
from datetime import datetime

# class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(100), unique=True, nullable=False)
#     password = db.Column(db.String(200), nullable=False)
#     income = db.Column(db.Float, default=0)
#     expenses = db.relationship('Expense', backref='user', lazy=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    income = db.Column(db.Float, default=0)

    expenses = db.relationship('Expense', backref='user', lazy=True)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10))  # Income or Expense
    category = db.Column(db.String(50))
    amount = db.Column(db.Float)
    date = db.Column(db.Date, default=datetime.utcnow)
    description = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
