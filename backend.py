#import ptvsd
import ast
import string

from flask import render_template, request, redirect, url_for, session
from utilities import *
from application import application_config, get_security_values
from flask_mail import Mail
from time import time
import random

# Allow other computers to attach to ptvsd at this IP address and port.
#ptvsd.enable_attach(address=('0.0.0.0', 5678), redirect_output=True)

# Pause the program until a remote debugger is attached
#ptvsd.wait_for_attach()

app = Flask(__name__)
print(app)
app = application_config(app)
mail = Mail(app)

failed_signin_attempts = {}
blocked_ips = {}


@app.before_request
def limit_signin_attempts():
    ip_address = request.remote_addr
    signin_attempts, block_time = get_security_values()

    if ip_address in blocked_ips:
        if blocked_ips[ip_address] < time():
            del blocked_ips[ip_address]
            failed_signin_attempts[ip_address] = 0
        else:
            remaining_time = blocked_ips[ip_address] - time()
            return f"Your IP is blocked for {remaining_time} seconds", 403

    failed_signin_attempts[ip_address] = failed_signin_attempts.get(ip_address, 0)

    if failed_signin_attempts[ip_address] >= signin_attempts:
        blocked_ips[ip_address] = time() + block_time
        return f"Your IP is blocked for {block_time} seconds", 403


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('signin'))
    #return "Hello, Flask!"

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user_data = fetch_user_data_from_db(username=username)
        if user_data is None:
            flash('User does not exist')
            return redirect(url_for('signin'))

        salt_bytes = bytes.fromhex(get_user_salt(user_id=user_data['user_id']))
        signin_hashed_pwd = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt_bytes, 100000)
        user_hashed_password = bytes.fromhex(user_data['password'])

        if user_hashed_password == signin_hashed_pwd:
            session['username'] = username
            session['user_id'] = user_data['user_id']
            failed_signin_attempts[request.remote_addr] = 0
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            failed_signin_attempts[request.remote_addr] += 1
            return redirect(url_for('signin'))

    return render_template(
        'signin.html',
        user_added=request.args.get('user_added'), password_changed=request.args.get("password_changed"))


@app.route('/signout')
def signout():
    session.clear()
    return redirect(url_for('signin'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    _, salt_len = get_password_policy()
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        new_email = request.form.get('email')
        if check_if_user_exists_using_email(new_email):
            flash("Email already exists! please use different email or signin to your account.")
            return redirect(url_for('register'))
        if not validate_password(new_password):
            return redirect(url_for('register'))
        publish_regions = request.form.getlist('publish_regions[]')

        user_data = fetch_user_data_from_db(username=new_username)
        if user_data:
            flash('Username already exists')
            return redirect(url_for('register'))
        new_password_hashed_hex, user_salt_hex = generate_new_password_hashed(new_password, generate_to_hex=True)
        add_new_user_to_db(
            new_username,
            new_password_hashed_hex,
            new_email,
            user_salt_hex)
        user_id = fetch_user_data_from_db(username=new_username)['user_id']
        add_user_regions_selected_to_db(publish_regions, user_id)
        session['username'] = new_username
        session['user_id'] = user_id
        return redirect(url_for('signin', user_added="user added"))

    regions = fetch_all_regions_names_from_db()
    return render_template('register.html', regions=regions)


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('signin'))
    username = session['username']
    customer_data = request.args.getlist('customer_data')
    if customer_data == ['False']:
        return render_template('dashboard.html', username=username, customer_data=customer_data)
    if customer_data != []:
        customer_data = [ast.literal_eval(data) for data in customer_data]
        return render_template('dashboard.html', username=username, customer_data=customer_data)
    return render_template('dashboard.html', username=username)


@app.route('/add_new_customer', methods=['GET', 'POST'])
def add_new_customer():
    if 'username' not in session:
        return redirect(url_for('signin'))

    if request.method == 'POST':
        fields = [
            'region_id',
            'package_name',
            'ssn',
            'first_name',
            'last_name',
            'email',
            'phone',
            'address']
        customer_data = {field: request.form.get(field) for field in fields}
        customer_data['agent_id'] = session['user_id']
        customer_id = add_new_customer_to_db(customer_data)
        return redirect(url_for('dashboard', customerid=customer_id))

    regions = fetch_user_regions(session['user_id'])
    return render_template('add_new_customer.html', regions=regions)


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    user_data = session.get('user_data')
    username = session.get("username")
    if not user_data and not username:
        return redirect(url_for('index'))
    if request.method == "POST":
        if not user_data:
            user_data = fetch_user_data_from_db(username=username)
        if user_data:
            user_email = user_data["email"]
            new_password = request.form.get('new_pwd')
            old_password = request.form.get('old_pwd')

            if (isinstance(old_password, str)):
                if not compare_to_current_password(user_data, old_password):
                    flash("The old password you inserted does not match the current user password.\nPlease try again")
                    return redirect(url_for('change_password', _method='GET'))

                if not validate_password(new_password):
                    return redirect(url_for('change_password', _method='GET'))

                if change_user_password_in_db(user_email, new_password):
                    return redirect(url_for('signin', password_changed=True))

            else:  # reset from email
                if not validate_password(new_password):
                    return redirect(url_for('change_password', emailReset=True))
                if change_user_password_in_db(user_email, new_password):
                    return redirect(url_for('signin', password_changed=True))
                return redirect(url_for('change_password', emailReset=True))

    return render_template('change_password.html', emailReset=request.args.get('emailReset'))

@app.route("/password_reset_email", methods=["GET", "POST"])
def password_reset_email():
    if request.method == "POST":
        token = request.form.get("token")
        return redirect(url_for('password_change', token=token))
    return render_template('password_reset_email.html')


@app.route("/password_change/<string:token>", methods=["GET", "POST"])
def password_change(token):
    if request.method == "GET":
        user_data = check_if_reset_token_exists(token)
        if user_data:
            session['user_data'] = user_data
            return redirect(url_for('change_password', emailReset=True))
        flash('The code was not valid', 'error')
        return render_template('password_reset.html')


@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == 'POST':
        user_email = request.form["email"]
        if check_if_user_exists_using_email(email=user_email):
            random_string = ''.join(
                random.choices(
                    string.ascii_uppercase +
                    string.digits,
                    k=20))
            hash_code = hashlib.sha1(
                random_string.encode('utf-8')).digest().hex()

            # Insert password reset info into the database
            update_password_reset(user_email, hash_code)
            # Send email with the random string (randomly generated token)
            send_email(
                mail=mail,
                recipient=user_email,
                hash_code=random_string)

            flash('An email was sent check your mailbox', 'info')
            return redirect(url_for('password_reset_email'))
        else:
            flash('The user does not exist', 'error')
            return redirect(url_for('password_reset'))
    else:
        return render_template('password_reset.html')


@app.route('/search_customer_data', methods=['POST'])
def search_customer_data():
    customer_first_name = request.form.get('first_name')
    customer_last_name = request.form.get('last_name')
    customer_data = fetch_customer_data_by_name(customer_first_name, customer_last_name)
    if customer_data:
        return redirect(url_for('dashboard', customer_data=customer_data))
    return redirect(url_for('dashboard', customer_data=False))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
    
