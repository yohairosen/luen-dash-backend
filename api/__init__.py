# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os, json

from flask import Flask
from flask_cors import CORS

from .routes import rest_api
from .models import db
from flask_migrate import Migrate

app = Flask(__name__)

app.config.from_object('api.config.BaseConfig')

db.init_app(app)
rest_api.init_app(app)
CORS(app)

migrate = Migrate(app, db)

# Setup database
@app.before_first_request
def initialize_database():
    try:
        db.create_all()
    except Exception as e:

        print('> Error: DBMS Exception: ' + str(e) )

        # fallback to SQLite
        BASE_DIR = os.path.abspath(os.path.dirname(__file__))

        print('> Error: DBMS Exception: ' + str(e))

        # Choose the SQLite file based on FLASK_ENV
        flask_env = app.config.get('FLASK_ENV', 'development')
        sqlite_file = 'db_prod.sqlite3' if flask_env == 'production' else 'db.sqlite3'
        sqlite_uri = 'sqlite:///' + os.path.join(BASE_DIR, sqlite_file)

        # Fallback to the appropriate SQLite file
        app.config['SQLALCHEMY_DATABASE_URI'] = sqlite_uri
        print(f'> Fallback to SQLite: {sqlite_file}')
        db.create_all()

"""
   Custom responses
"""

@app.after_request
def after_request(response):
    """
       Sends back a custom error with {"success", "msg"} format
    """

    if int(response.status_code) >= 400:
        response_data = json.loads(response.get_data())
        if "errors" in response_data:
            response_data = {"success": False,
                             "msg": list(response_data["errors"].items())[0][1]}
            response.set_data(json.dumps(response_data))
        response.headers.add('Content-Type', 'application/json')
    return response
