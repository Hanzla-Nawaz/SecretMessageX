from flask import Flask, render_template, request, redirect, url_for, flash, session
from utils.encryption import encode, decode
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Mock authentication (replace with real database/authentication system)
users = {"admin": generate_password_hash("password")}  # Store hashed passwords

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash('Username already exists. Please choose a different one.', 'error')
        else:
            users[username] = generate_password_hash(password)
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
    return render_template('signup.html')
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')


from flask import Flask, render_template, url_for
# Define the 'encrypt' endpoint
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    # Your encryption logic here
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    # Your decryption logic here
    return render_template('decrypt.html')

@app.route('/logout')
def logout():
    # Your logout logic here
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

