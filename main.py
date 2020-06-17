# FLask modules 
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Utilities
import os
import uuid
import jwt
import datetime
from functools import wraps

# App initialization
app = Flask(__name__)


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

""" Auth decorators """
def token_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = None

        # Check if the user send the token
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({ 'message': 'Token is missing!' }), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.get(data['id'])
        except:
            return jsonify({ 'message': 'Token is invalid!' }), 401

        return func(current_user, *args, **kwargs)
    
    return wrapped

""" User routes """
@app.route('/users', methods=['GET'])
@token_required
def get_users(current_user):
    # getting users from database
    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['name'] = user.name
        user_data['is_admin'] = user.is_admin
        output.append(user_data)
    
    return jsonify({ 'users': output})


@app.route('/users/<user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({ 'message': 'User not found'})

    user_data  = {}
    user_data['id'] = user.id
    user_data['name'] = user.name
    user_data['is_admin'] = user.is_admin

    return jsonify({ 'user': user_data })


@app.route('/users', methods=['POST'])
@token_required
def create_user(current_user):
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(id=str(uuid.uuid4()), name=data['name'], password=hashed_password, is_admin=False)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({ 'message': 'new user created' })

@app.route('/users/<user_id>', methods=['PUT'])
@token_required
def set_admin(current_user, user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({ 'message': 'user not found' })

    user.is_admin = not user.is_admin
    db.session.commit()

    message = 'The user has been promoted to admin' if user.is_admin else 'The user has been demoted'
    return jsonify({ 'message' : message })

@app.route('/users/<user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({ 'message': 'User not found' })
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({ 'message': 'The user has been deleted' })

"""  Auth routes """
@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, { 'WWW-Authenticate': 'Basic realm="Login Required!"' })
    
    user =  User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, { 'WWW-Authenticate': 'Basic realm="Login Required!"' })

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({ 'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30) },
                           app.config['SECRET_KEY'])
        
        return jsonify({ 'token': token.decode('UTF-8') })



# Run server
if __name__ == '__main__':
    app.run(debug=True)