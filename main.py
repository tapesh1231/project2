from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Generate a secure random secret key using secrets module
app.secret_key = secrets.token_hex(16)  # Generates a random 16-byte key

# MySQL Database Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # Replace with your MySQL password
app.config['MYSQL_DB'] = 'apnavision'  # Replace with your MySQL database name

mysql = MySQL(app)

@app.before_request
def before_request():
    # Make session data available globally
    g.loggedin = 'loggedin' in session
    g.username = session.get('username')

@app.route('/')
def home():
    return render_template('index.html', loggedin=g.loggedin, username=g.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        print(f"Login attempt for username: {username}")
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            print(f"Account found: {account['username']}")
            print(f"Stored hash: {account['password']}")
            print(f"Password entered: {password}")

            if check_password_hash(account['password'], password):
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                print(f"Login successful for username: {username}")
                return redirect(url_for('home'))
            else:
                msg = 'Incorrect username / password!'
                print(f"Incorrect password for username: {username}")
        else:
            msg = 'Account not found!'
            print(f"Account not found for username: {username}")
    return render_template('login.html', msg=msg)

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    print("Logged out successfully")
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        print(f"Register attempt for username: {username}")
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            msg = 'Account already exists!'
            print(f"Account already exists for username: {username}")
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
            print(f"Invalid email address: {email}")
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
            print(f"Invalid username: {username}")
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
            print("Form incomplete")
        else:
            # Use scrypt hashing for consistency
            hashed_password = generate_password_hash(password, method='scrypt')
            print(f"Hashed password: {hashed_password}")
            cursor.execute('INSERT INTO accounts (username, password, email) VALUES (%s, %s, %s)', (username, hashed_password, email))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
            print(f"User {username} successfully registered")
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
        print("Form incomplete")
    return render_template('register.html', msg=msg)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/courses')
def courses():
    return render_template('courses.html')

@app.route('/trainers')
def trainers():
    return render_template('trainers.html')

@app.route('/events')
def events():
    return render_template('events.html')

@app.route('/adminDashboard')
def adminDashboard():
    return render_template('adminDashboard.html')


@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/course-details')
def course_details():
    return render_template('course-details.html')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
