from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = "mermaidsAreReal"
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'login_registration')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
ALL_LETTERS = re.compile(r'^[a-zA-Z]+$')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/success')
def success():
    print session
    return render_template('success.html')

@app.route('/validate', methods=['POST'])
def validate():
    if request.form['submit'] == 'Register':
        # Validate First Name Value
        if len(request.form['first_name']) >= 2 and ALL_LETTERS.match(request.form['first_name']):
            first_name = request.form['first_name']
        else:
            flash('User first name must be at least 2 characters and only non-numeric values.')

        # Validate Last Name Value
        if len(request.form['last_name']) >= 2 and ALL_LETTERS.match(request.form['last_name']):
            last_name = request.form['last_name']
        else:
            flash('User last name must be at least 2 characters and only non-numeric values.')

        # Validate Email Value
        if len(request.form['email']) > 0 and EMAIL_REGEX.match(request.form['email']):
            email = request.form['email']
        else:
            flash('Please enter a valid email address.')

        # Validate Password Value
        if len(request.form['pw']) >= 8:
            pw_hash = bcrypt.generate_password_hash(request.form['pw'])
        else:
            flash('Password must be at least 8 characters long.')

        # Validate Password Confirmation Value
        if request.form['pw'] != request.form['pw_confirm']:
            flash('Passwords must match.')

        # Route based on Flashes
        if '_flashes' in session:
            return redirect('/register')
        else:
            query = "INSERT INTO users (first_name, last_name, email, pw_hash, created_at) VALUES (:first_name, :last_name, :email, :pw_hash, NOW())"
            data = {
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'pw_hash': pw_hash
            }
            mysql.query_db(query, data)

            userId = mysql.query_db("SELECT id FROM users WHERE email = :email LIMIT 1", data)
            session['id'] = userId[0]['id']
            return redirect('/success')

    elif request.form['submit'] == 'Login':
        password = request.form['pw']
        query = 'SELECT * FROM users WHERE email = :email LIMIT 1'
        data = {
            'email': request.form['email']
        }
        user = mysql.query_db(query, data)

        if bcrypt.check_password_hash(user[0]['pw_hash'], request.form['pw']):
            userId = mysql.query_db("SELECT id FROM users WHERE email = :email LIMIT 1", data)
            session['id'] = userId[0]['id']
            return redirect('/success')
        else:
            flash('Invalid Password')
            return redirect('/')

app.run(debug=True)
