# FLask modules 
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# App initialization
app = Flask(__name__)

# Utilities
import os

app.config['SECRET_KEY'] = b'\x91\xa3\xb2T\x88\xe0\xa78\x05f\xdd\x14\x1ed\xcc:'
db_path = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(db_path, 'test.db') 

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean())
    todos = db.relationship('Todo', backref='user', lazy=True)

class Todo(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    text = db.Column(db.String(50), unique=True)
    complete = db.Column(db.Boolean())
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)


# Run server
if __name__ == '__main__':
    app.run(debug=True)