from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
import mysql.connector
import secrets
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Database configurations
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # Default password for XAMPP is empty
    'database': 'mydatabase'  # Name of your database
}

def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn

def generate_reset_token():
    return secrets.token_urlsafe(16)

def generate_username(name):
    username = name.lower().replace(" ", "") + secrets.token_hex(4)
    return username

def send_welcome_email(to_email, username):
    smtp_server = "smtp.example.com"
    smtp_port = 587
    smtp_username = "your_email@example.com"
    smtp_password = "your_password"

    subject = "Welcome to Our Service!"
    body = f"Dear {username},\n\nThank you for signing up!\n\nBest regards,\nYour Company"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_username
    msg["To"] = to_email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_username, to_email, msg.as_string())

app.secret_key = 'your_secret_key'

# Configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.yourmailserver.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

mail = Mail(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phoneno = request.form['phoneno']
        password = request.form['password']

        username = generate_username(name)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email, phoneno, password, username) VALUES (%s, %s, %s, %s, %s)", 
                       (name, email, phoneno, hashed_password, username))
        conn.commit()
        cursor.close()
        conn.close()

        send_welcome_email(email, username)

        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email, phoneno, password FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[4], password):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            session['user_email'] = user[2]
            return redirect(url_for('dashboard'))  # Redirect to dashboard upon successful login
        else:
            flash('Invalid email or password', 'error')

        cursor.close()
        conn.close()

    return render_template('login.html')

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user:
            reset_token = generate_reset_token()
            cursor.execute("UPDATE users SET reset_token=%s WHERE email=%s", (reset_token, email))
            conn.commit()

            reset_url = url_for('reset_password', token=reset_token, _external=True)
            subject = "Password Reset Request"
            body = f"Please click the link to reset your password: {reset_url}"
            msg = Message(subject, recipients=[email], body=body)
            mail.send(msg)

            flash('Password reset link sent to your email', 'success')
        else:
            flash('Email address not found', 'error')

        cursor.close()
        conn.close()

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_password', token=token))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=%s, reset_token=NULL WHERE reset_token=%s", (hashed_password, token))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Your password has been updated', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user_name=session.get('user_name'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        if not name or not email or not message:
            flash('Please enter all the fields', 'error')
        else:
            msg = Message(subject=f"Message from {name}",
                          sender=email,
                          recipients=['your_email@example.com'],
                          body=message)
            mail.send(msg)
            flash('Message sent successfully!', 'success')
    return render_template('contact.html')

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.run(debug=True)
