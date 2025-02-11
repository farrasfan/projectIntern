import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import environ

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('DB_URL')

    db.init_app(app)

    return app 
