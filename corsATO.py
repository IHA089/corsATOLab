import logging
from flask import Flask, request, make_response, render_template, session, jsonify, redirect, url_for
from functools import wraps
from flask_cors import CORS 
import jwt as pyjwt
import uuid, datetime, sqlite3, hashlib, random, os

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


lab_type = "AccountTakeover"
lab_name = "corsATOLab"

user_data = {}

corsATO = Flask(__name__)
corsATO.secret_key = "vulnerable_lab_by_IHA089"
CORS(corsATO, resources={r"/*": {"origins": "*"}})

JWT_SECRET = "MoneyIsPower"

def create_database():
    db_path = os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        gmail TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        uuid TEXT NOT NULL
    )
    ''')

    numb = random.randint(100, 999)
    passw = "admin@"+str(numb)
    passw_hash = hashlib.md5(passw.encode()).hexdigest()
    user_uuid = str(uuid.uuid4())
    query = "INSERT INTO users (gmail, username, password, uuid) VALUES ('admin@iha089.org', 'admin', '"+passw_hash+"', '"+user_uuid+"')"
    cursor.execute(query)
    conn.commit()
    conn.close()

def check_database():
    db_path = os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    if not os.path.isfile(db_path):
        create_database()

check_database()

def get_db_connection():
    db_path=os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def check_cookies():
    user_uuid = request.cookies.get("uuid")
    jwt_token = request.cookies.get("jwt_token")

    if user_uuid in user_data and jwt_token == user_data[user_uuid]:
        decoded = pyjwt.decode(jwt_token, JWT_SECRET, algorithms="HS256")
        session['user'] = decoded['username']
        return True
    else:
        return False

@corsATO.route('/')
def home():
    if not check_cookies():
        session.clear()
    return render_template('index.html', user=session.get('user'))

@corsATO.route('/index.html')
def index_html():
    if not check_cookies():
        session.clear()
    return render_template('index.html', user=session.get('user'))

@corsATO.route('/login.html')
def login_html():
    if not check_cookies():
        session.clear()
    return render_template('login.html')

@corsATO.route('/join.html')
def join_html():
    if not check_cookies():
        session.clear()
    return render_template('join.html')

@corsATO.route('/acceptable.html')
def acceptable_html():
    if not check_cookies():
        session.clear()
    return render_template('acceptable.html', user=session.get('user'))

@corsATO.route('/term.html')
def term_html():
    if not check_cookies():
        session.clear()
    return render_template('term.html', user=session.get('user'))

@corsATO.route('/privacy.html')
def privacy_html():
    if not check_cookies():
        session.clear()
    return render_template('privacy.html', user=session.get('user'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        check_cookies()
        if 'user' not in session:  
            return redirect(url_for('login_html', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@corsATO.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user_uuid = request.cookies.get("uuid")
        jwt_token = request.cookies.get("jwt_token")

        if user_uuid in user_data and jwt_token == user_data[user_uuid]:
            decoded = pyjwt.decode(jwt_token, JWT_SECRET, algorithms="HS256")
            session['user'] = decoded['username']
            return redirect(url_for('dashboard'))

        return render_template('login.html')

    username = request.form.get('username')
    password = request.form.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()
    hash_password = hashlib.md5(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE username = ? or gmail = ? AND password = ?", (username, username, hash_password))
    user = cursor.fetchone()
    conn.close()

    if user:
        session['user'] = username
        user_uuid = user['uuid'] if 'uuid' in user else str(uuid.uuid4())

        jwt_token = pyjwt.encode({
            "username": username,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")

        user_data[user_uuid] = jwt_token

        if 'uuid' not in user:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET uuid = ? WHERE username = ?", (user_uuid, username))
            conn.commit()
            conn.close()

        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie("uuid", user_uuid, httponly=False)  # Insecure cookie
        response.set_cookie("jwt_token", jwt_token, httponly=True, samesite="Strict")
        return response

    error_message = "Invalid username or password. Please try again."
    return render_template('login.html', error=error_message)

@corsATO.route('/get-token', methods=['GET', 'POST'])
def get_token():
    user_uuid = request.cookies.get("uuid")

    if not user_uuid:
        return jsonify({"message": "UUID not found in cookies."}), 400

    if user_uuid in user_data:
        jwt_token = user_data[user_uuid]
        return jsonify({"uuid": user_uuid, "jwt_token": jwt_token})

    return jsonify({"message": "Invalid UUID"}), 404

@corsATO.route('/protected', methods=['GET'])
def protected():
    jwt_token = request.cookies.get("jwt_token")
    if not jwt_token:
        return jsonify({"message": "Missing JWT token"}), 401

    try:
        decoded = pyjwt.decode(jwt_token, JWT_SECRET, algorithms="HS256")
        return jsonify({"message": "Access granted", "data": decoded})
    except pyjwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except pyjwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

@corsATO.route('/join', methods=['GET', 'POST'])
def join():
    if not check_cookies():
        session.clear()
    if 'user' in session:
        return render_template('dashboard.html', user=session.get('user'))

    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('password')
    if not email.endswith('@iha089.org'):
        error_message = "Only email with @iha089.org domain is allowed."
        return render_template('join.html', error=error_message)
    conn = get_db_connection()
    cursor = conn.cursor()
    hash_password = hashlib.md5(password.encode()).hexdigest()
    query = f"INSERT INTO users (gmail, username, password) VALUES ('{email}', '{username}', '{hash_password}')".format(email, username, password)
    cursor.execute("SELECT * FROM users where gmail = ?", (email,))
    if cursor.fetchone():
        error_message = "Email already taken. Please choose another."
        conn.close()
        return render_template('join.html', error=error_message)
    
    try:
        user_uuid = str(uuid.uuid4())

        cursor.execute("INSERT INTO users (gmail, username, password, uuid) VALUES (?, ?, ?, ?)", (email, username, hash_password, user_uuid))
        conn.commit()

        response = make_response(render_template('login.html'))
        response.set_cookie("uuid", user_uuid, httponly=False)  # Insecure cookie
        return response

    except sqlite3.Error:
        error_message = "Something went wrong. Please try again later."
        return render_template('join.html', error=error_message)
    finally:
        conn.close()
    

@corsATO.route('/dashboard')
@corsATO.route("/dashboard.html")
@login_required
def dashboard():
    if not check_cookies():
        session.clear()
    if 'user' not in session:
        return redirect(url_for('login_html'))
    admin_list=['admin', 'administrator']
    if session.get('user') in admin_list:
        return render_template('admin-dashboard.html', user=session.get('user'))

    return render_template('dashboard.html', user=session.get('user'))

@corsATO.route('/logout.html')
def logout():
    session.clear() 
    response = make_response(redirect(url_for('login_html')))
    response.set_cookie("uuid", "", httponly=False)  # Insecure cookie
    response.set_cookie("jwt_token", "", httponly=True, samesite="Strict")
    return response

@corsATO.route('/profile')
@corsATO.route('/profile.html')
@login_required
def profile():
    if not check_cookies():
        session.clear()
    if 'user' not in session:
        return redirect(url_for('login_html'))
    return render_template('profile.html', user=session.get('user'))

@corsATO.after_request
def add_cache_control_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response
