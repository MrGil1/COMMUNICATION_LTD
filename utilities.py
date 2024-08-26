#import ptvsd
import mysql.connector
import os
import time
from dotenv import load_dotenv
from flask import flash
from application import *
from flask_mail import Message
import hashlib

# Allow other computers to attach to ptvsd at this IP address and port.
#ptvsd.enable_attach(address=('0.0.0.0', 5678), redirect_output=True)

# Pause the program until a remote debugger is attached
#ptvsd.wait_for_attach()

load_dotenv()
password = os.getenv('MYSQL_ROOT_PASSWORD')
server = os.getenv('MYSQL_HOST', 'my_mysql_container')
port = int(os.getenv('MYSQL_PORT', 3307))

while True:
    try:
        conn = mysql.connector.connect(host=server,user="root",password=password,database="CommunicationLTD")
        break
    except mysql.connector.Error as err:
        print(f"Gili!!!! Error: {err}")
        time.sleep(5)

#conn = mysql.connector.connect(host=server,user="root",password=password,database="CommunicationLTD")


def fetch_user_data_from_db(username=None, password=None):
    with conn.cursor(dictionary=True) as cursor:
        if username and password:
            cursor.execute(
                "SELECT * FROM users WHERE username = %s AND password = %s",
                (username, password))
        else:
            cursor.execute(
                f"SELECT * FROM users WHERE username = %s", (username,))
        return cursor.fetchone()


def fetch_all_regions_names_from_db():
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("SELECT region_name FROM regions")
        regions = cursor.fetchall()
        regions = [region['region_name'] for region in regions]
    return regions


def add_new_customer_to_db(customer_data):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            "INSERT INTO customers (agent_id, region_id, package_name, ssn, first_name, last_name, email, phone, address) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (customer_data['agent_id'],
             customer_data['region_id'],
             customer_data['package_name'],
             customer_data['ssn'],
             customer_data['first_name'],
             customer_data['last_name'],
             customer_data['email'],
             customer_data['phone'],
             customer_data['address']))
        customer_id = cursor.lastrowid
    conn.commit()
    return customer_id


def fetch_user_regions(user_id):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            "SELECT region_name, regions.region_id FROM regions JOIN user_regions ON regions.region_id = user_regions.region_id WHERE user_id = %s",
            (user_id,))
        regions = cursor.fetchall()
        regions = [(region['region_name'], region['region_id'])
                   for region in regions]
    return regions


def fetch_customer_data(customer_id):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            "SELECT * FROM customer_view WHERE customer_id = %s", (customer_id,))
        return cursor.fetchone()


def fetch_customer_data_by_name(first_name, last_name):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            "SELECT * FROM customer_view WHERE first_name = %s AND last_name = %s", (first_name, last_name))
        return cursor.fetchall()


def get_user_salt(user_id):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            "SELECT * FROM user_info WHERE user_id = %s", (user_id,))
        return cursor.fetchone()['salt']


def check_if_user_exists_using_email(email: str) -> bool:
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("SELECT * FROM users WHERE email = %s ", (email,))
        if cursor.fetchone(): #
            return True
        return False


def add_new_user_to_db(new_username, new_password, new_email, salt):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
            (new_username, new_password, new_email))
        user_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO user_info (user_id,salt) VALUES (%s, %s)",
            (user_id, salt))
        cursor.execute(
            "INSERT INTO password_history (user_id, password, salt) VALUES (%s, %s, %s)",
            (user_id, new_password, salt))


def add_user_regions_selected_to_db(publish_regions, user_id):
    with conn.cursor(dictionary=True) as cursor:
        for region in publish_regions:
            cursor.execute(
                "SELECT region_id FROM regions WHERE region_name = %s",
                (region,))
            region_id = cursor.fetchone()['region_id']
            cursor.execute(
                "INSERT INTO user_regions (user_id, region_id) VALUES (%s, %s)",
                (user_id, region_id))
    conn.commit()


def validate_password(password) -> bool:
    password_policy, _ = get_password_policy()
    with open(os.path.abspath('passwords.txt'), 'r') as common_passwords_file:
        for common_pwd in common_passwords_file:
            if password == common_pwd.strip():
                flash('Password is a known password.')
                return False
    rules_messages = password_rules_messages()
    if len(password_policy.test(password)) > 0:
        flash('The Password does not meet the minimum requirements ', 'error')
        for missing_requirement in password_policy.test(password):
            splitted = str(missing_requirement).split("(")
            number = splitted[1].replace(")", "")
            flash(
                "Please enter a password with at least " + number + " " +
                rules_messages[splitted[0]])
        return False
    else:
        return True


def update_password_reset(email, hash_code):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            '''UPDATE users SET reset_token = %s WHERE email = %s''',
            (hash_code, email))
        conn.commit()


def send_email(mail, recipient, hash_code):
    msg = Message(
        "Confirm Password Change",
        sender="communicationltdpassreset@gmail.com",
        recipients=[recipient],
    )
    msg.body = (
        "Hello,\nWere Here To  Help, We've received a request to reset your password.\n "
        "click the link below and enter your new password\n\n\n\n http://localhost:8000/password_change/"
        + hash_code
        + "\n\n\n\nOr enter the following code in the password reset page: "
        + hash_code
        +"\n\n\n\nSincerely , The COMMUNICATION LTD Team."
    )
    mail.send(msg)


def change_user_password_in_db(email, new_password) -> bool:
    # Check if the new password matches any of the previous passwords
    if check_previous_passwords(email, new_password):
        flash(
            "This password has been used before, Please enter a new password. ")
        return False
    new_password_hashed_hex, user_salt_hex = generate_new_password_hashed(new_password, generate_to_hex=True)

    # Update the user's password in the database
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            '''UPDATE users SET password = %s WHERE email = %s''',
            (new_password_hashed_hex, email))
        cursor.execute(
            '''UPDATE user_info SET salt = %s WHERE user_id = (SELECT user_id FROM users WHERE email = %s)''',
            (user_salt_hex, email))
        cursor.execute(
            '''INSERT INTO password_history (user_id,password,salt) VALUES ((SELECT user_id FROM users WHERE email = %s), %s, %s)''',
            (email, new_password_hashed_hex, user_salt_hex))
        conn.commit()
    return True


def check_previous_passwords(email, user_new_password):
    with conn.cursor(dictionary=True) as cursor:
        # Get the user_id based on the email
        cursor.execute('''SELECT user_id FROM users WHERE email = %s''', (email,))
        user_id = cursor.fetchone()['user_id']

        # Retrieve the previous three passwords for the user
        cursor.execute(
            '''SELECT * FROM (
                SELECT * FROM password_history 
                WHERE user_id = %s 
                ORDER BY history_id DESC 
                LIMIT 3
            ) AS recent_passwords 
            ORDER BY history_id DESC;''',
            (user_id,))
        previous_passwords_data = [(row['password'], row['salt']) for row in cursor.fetchall()]
        return compare_passwords(user_new_password, previous_passwords_data)


def compare_passwords(user_new_password, previous_passwords_data) -> bool:
    for previous_password, previous_salt in previous_passwords_data:
        previous_salt_bytes = bytes.fromhex(previous_salt)
        user_salted_password = hashlib.pbkdf2_hmac(
            'sha256', user_new_password.encode('utf-8'),
            previous_salt_bytes, 100000)
        if user_salted_password == bytes.fromhex(previous_password):
            return True
    return False


def compare_to_current_password(user_data, password) -> bool:
    current_password = user_data['password']
    current_salt = bytes.fromhex(get_user_salt(user_data['user_id']))
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'),
        current_salt, 100000)
    if hashed_password == bytes.fromhex(current_password):
        return True
    else:
        return False


def generate_new_password_hashed(new_password, generate_to_hex=False):
    _, salt_len = get_password_policy()
    user_salt = os.urandom(salt_len)
    new_password_hashed = hashlib.pbkdf2_hmac(
        'sha256', new_password.encode('utf-8'),
        user_salt, 100000)  # save in bytes
    if generate_to_hex:
        return new_password_hashed.hex(), user_salt.hex()
    return new_password_hashed, user_salt


def check_if_reset_token_exists(reset_token):
    with conn.cursor(dictionary=True) as cursor:
        hashed_token = hashlib.sha1(
            reset_token.encode('utf-8')).digest().hex()
        cursor.execute(
            '''SELECT * FROM users WHERE reset_token = %s''',
            (hashed_token,))
        return cursor.fetchone()
