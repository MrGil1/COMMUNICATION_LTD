from flask import Flask
from dotenv import load_dotenv
import os
import json

from password_strength import PasswordPolicy

SALT_LENGTH = 32
FAILED_SIGNIN_ATTEMPTS = 3
BLOCK_TIME_SECONDS = 300

def application_config(app: Flask):
    load_dotenv()
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = 'communicationltdpassreset@gmail.com'
    app.config['MAIL_PASSWORD'] = 'bdar waxi kbwf bjcs'
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    app.secret_key = os.getenv('MYSQL_ROOT_PASSWORD')
    return app

def get_security_values():
    return FAILED_SIGNIN_ATTEMPTS, BLOCK_TIME_SECONDS

def get_password_policy():
    file = open("password_config.json")
    password_config = json.load(file)["password_requirements"]
    policy = PasswordPolicy.from_names(
        length=password_config["password_len"],  # min length: 10
        # need min. 1 uppercase letters
        uppercase=password_config["uppercase"],
        numbers=password_config["numbers"],  # need min. 1 digits
        # need min. 1 special characters
        special=password_config["special_char"],
        # need min. 1 non-letter characters (digits, specials, anything)
        nonletters=password_config["nonletters"]
    )
    return policy, password_config["salt_len"]


def password_rules_messages():
    file = open("password_config.json")
    return json.load(file)["rules_messages"]
