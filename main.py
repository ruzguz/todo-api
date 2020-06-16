# FLask modules 
from flask import Flask
from flask_sqlalchemy import SQLAlchemy


# App initialization
app = Flask(__name__)

app.config['SECRET_KEY'] = b'\x91\xa3\xb2T\x88\xe0\xa78\x05f\xdd\x14\x1ed\xcc:'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'

db = SQLAlchemy(app)

# Run server
if __name__ == '__main__':
    app.run(debug=True)