# FLask modules 
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import validates

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

    @validates('name')
    def validate_username(self, key, name):
        assert User.query.filter_by(name=name), 'This username already exists'
        return name


class Todo(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    text = db.Column(db.String(50), unique=True)
    complete = db.Column(db.Boolean())
    user_id = db.Column(db.String(50), db.ForeignKey('user.id'), nullable=False)

""" Auth decorators """
def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = None

        # Check if the user sent the token
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        # if user does not sent the token return an error
        if not token:
            message = jsonify({ 'message': 'Token is missing' })
            return make_response(message, 401, { 'WWW-Authenticate': 'Basic realm="Login Required!"' })

        try:
            # Decoding the token
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.get(data['id'])
        except:
            # Return error message if the token is invalid
            message = jsonify({ 'message': 'Token is invalid!' })
            return make_response(message, 401, { 'WWW-Authenticate': 'Basic realm="Login Required!"' })

        return func(current_user, *args, **kwargs)
    
    return wrapper



""" Test routes """
@app.route('/hello', methods=['GET'])
def test():
    return jsonify({ 'message': 'Hello world!!!' })


@app.route('/seed-db', methods=['GET'])
def load_initial_users():
    admin = User(id=str(uuid.uuid4()), name='admin', is_admin=True, password=generate_password_hash('1234'))
    user1 = User(id=str(uuid.uuid4()), name='user1', is_admin=False, password=generate_password_hash('1234'))
    user2 = User(id=str(uuid.uuid4()), name='user2', is_admin=False, password=generate_password_hash('1234'))
    user3 = User(id=str(uuid.uuid4()), name='user3', is_admin=False, password=generate_password_hash('1234'))
    db.session.add(admin); db.session.add(user1); db.session.add(user2); db.session.add(user3)
    db.session.commit()

    return jsonify({ 'message': 'Inital data loaded' })


""" User routes """
@app.route('/users', methods=['GET'])
@token_required
def get_users(current_user):

    # Admin required
    if not current_user.is_admin:
        return jsonify({ 'message': 'You have to be admin to perform this function!' }), 403

    # getting users from database
    users = User.query.all()

    output = []

    for user in users:
        user_data = {
            'id': user.id,
            'name': user.name,
            'is_admin': user.is_admin
        }

        output.append(user_data)
    
    return jsonify({ 'users': output})


@app.route('/users/<user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({ 'message': 'User not found'}), 404


    if not current_user.is_admin and current_user.id != user_id:
        return jsonify({ 'message': 'You cannot see the information of another user' }), 403


    user_data  = {
            'id': user.id,
            'name': user.name,
            'is_admin': user.is_admin
        }

    return jsonify({ 'user': user_data })


@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(id=str(uuid.uuid4()), name=data['name'], password=hashed_password, is_admin=False)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({ 'message': 'new user created' })

@app.route('/users/<user_id>', methods=['PUT'])
@token_required
def set_admin(current_user, user_id):

    # Admin required
    if not current_user.is_admin:
        return jsonify({ 'message': 'You have to be admin to perform this function!' })

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

    # Admin required
    if not current_user.is_admin:
        return jsonify({ 'message': 'You have to be admin to perform this function!' })

    user = User.query.get(user_id)

    if not user:
        return jsonify({ 'message': 'User not found' })
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({ 'message': 'The user has been deleted' })

"""  Auth routes """
@app.route('/login', methods=['POST'])
def login():
    # Getting auth information from request
    auth = request.authorization

    # Check if the server recive all auth information 
    if not auth or not auth.username or not auth.password:
        message = jsonify({ 'message': 'Could not verify, please introduce the username and the password' })
        return make_response(message, 401, { 'WWW-Authenticate': 'Basic realm="Login Required!"' })
    
    # Getting user from DB
    user =  User.query.filter_by(name=auth.username).first()

    # Check if user exists
    if not user:
        message = jsonify({ 'message': 'User doesn\'t exists' })
        return make_response( message, 401, { 'WWW-Authenticate': 'Basic realm="Login Required!"' })

    # Check user password
    if check_password_hash(user.password, auth.password):
        # Creating JWT
        token = jwt.encode({ 'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2) },
                           app.config['SECRET_KEY'])
        
        return jsonify({ 'token': token.decode('UTF-8') })
    else:
        message = jsonify({ 'message': 'The username and password you entered did not match our records.' })
        return make_response(message, 401, { 'WWW-Authenticate': 'Basic="Login required!"' })

""" Todos routes """
@app.route('/todos', methods=['GET'])
@token_required
def get_user_todos(current_user):
    todos =  Todo.query.filter_by(user_id=current_user.id)

    output = []

    for todo in todos:
        todo_data = {
            'id': todo.id,
            'text': todo.text,
            'complete': todo.complete,
        }

        output.append(todo_data)

    return jsonify({ 'todos': output })


@app.route('/todos', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)

    db.session.add(new_todo)
    db.session.commit()

    return jsonify({ 'message': 'Todo created' })

@app.route('/todos/<todo_id>', methods=['GET'])
@token_required
def get_todo(current_user, todo_id):
    todo = Todo.query.get(todo_id)

    if not todo:
        return jsonify({ 'message': 'Todo not found' }), 404
    

    todo_data = {
        'id': todo.id,
        'text': todo.text,
        'complete': todo.complete,
    }

    return jsonify({ 'todo': todo_data })

@app.route('/todos/<todo_id>', methods=['PUT'])
@token_required
def set_todo_status(current_user, todo_id):
    todo = Todo.query.get(todo_id)

    if not todo:
        return jsonify({ 'message': 'Todo not found' }), 404

    todo.complete = not todo.complete
    db.session.commit()

    message = 'The taks is complete' if todo.complete else 'The taks is incomplete'

    return jsonify({ 'message': message })

@app.route('/todos/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.get(todo_id)

    if not todo:
        return jsonify({ 'message': 'Todo not found' })

    db.session.delete(todo)
    db.session.commit()

    return jsonify({ 'message': 'Todo has been deleted' })

# Run server
if __name__ == '__main__':
    app.run(debug=True)