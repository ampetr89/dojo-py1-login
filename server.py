from flask import Flask, render_template, redirect, flash, request, session
from mysqlconnection import MySQLConnection
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = open('secret_key.txt', 'r').read().strip()

db = MySQLConnection(app, 'lang_app')
bcrypt = Bcrypt(app)

@app.route('/')
def home():
	if 'login' not in session:
		session['login'] = False
		
	if session['login']:
		return render_template('home.html', first_name=session['first_name'])
	else:
		return redirect('/login')
	

@app.route('/login')
def login():
	return render_template('login.html')


@app.route('/process-login', methods=['POST'])
def process_login():
	email = request.form['email']
	password = request.form['password']
	
	# first see if this user exists in the database
	user = db.query_db('select email, first_name, password_bcrypt from users \
		where email = :email', {'email': email})

	if len(user) > 0:
		# the user exists, now check they've supplied the correct password
		user = user[0]
		if bcrypt.check_password_hash(user['password_bcrypt'], password):
			# vaild email and password supplied
			session['login'] = True
			session['first_name'] = user['first_name']
		else:
			session['login'] = False
			flash('Password is not correct.', 'login-error')
	else:
		flash('No user found with this email.', 'login-error')

	return redirect('/')


@app.route('/register')
def register():
	return render_template('register.html')

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')

@app.route('/process-registration', methods=['POST'])
def process_registration():
	email = request.form['email']
	first_name = request.form['first_name']
	last_name = request.form['last_name']
	password = request.form['password']
	password2 = request.form['password2']
	
	session['register'] = False

	# check email is valid, username doesnt already exist
	user = db.query_db('select 1 from users where email = :email',
		{'email': email })
	if len(user) > 0:
		session['register'] = True
		flash('Account already exists with this email. Please log in.', 
			'registration-error')
		return redirect('/register')

	errors = []
	if not EMAIL_REGEX.match(email):
		errors.append('Invalid email format.')

	if len(first_name) < 3 or len(last_name) < 3:
		errors.append('First and last name must have at least 2 characters.')
	
	if len(password) < 8:
		errors.append('Password must be at least 8 characteres.')
	elif password != password2:
		errors.append('Passwords do not match.')
	
	for error in errors:
		flash(error, 'registration-error')

	if len(errors) > 0:
		return redirect('/register')

	# insert into db
	pw_encrypt = bcrypt.generate_password_hash(password)
	
	query = 'insert into users (email, first_name, last_name, password_bcrypt) \
	values(:email, :first_name, :last_name, :pw_encrypt)'
	params = {'first_name': first_name, 'last_name': last_name,
		'email': email, 'pw_encrypt': pw_encrypt}

	db.query_db(query, params)

	flash('Account created successfully. You may now log in.', 'registration-success')
	return redirect('/login')


@app.route('/logout')
def logout():
	session['login'] = False
	return redirect('/')

app.run(debug=True)
