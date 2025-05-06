import hashlib #for hashing
from flask import Flask, render_template, request, redirect, url_for, flash, session
import os 


app = Flask(__name__)
app.secret_key = 'secret_key_1234'


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Please try again!')
            return redirect(url_for('signup'))
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        with open ('credentials.txt', 'a') as f:
            f.write(email + ' ' + hashed_password + '\n')
        
        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email not in session:
            session[email] = 0  # Track attempts for this specific email

        if os.path.exists('locked.txt'):    
            with open('locked.txt', 'r') as locked_file:
                locked_emails = [line.strip() for line in locked_file]
            if email in locked_emails:
                flash('Your account has been locked due to too many failed login attempts.')
                return redirect(url_for('login'))
        
        hash_password = hashlib.sha256(password.encode()).hexdigest()
        login_success = False

        with open('credentials.txt', 'r') as f:
            for line in f:
                stored_email, stored_hash = line.strip().split()
                if email == stored_email and hash_password == stored_hash:
                    login_success = True
                    break
        
        if login_success:
            flash('Login successful! Welcome back.')
            session['email'] = email  # Save who is logged in
            session.pop(email, None)  # Reset attempt counter for this email
            return redirect(url_for('dashboard'))
        else:
            session[email] += 1
            if session[email] >= 3:
                with open('locked.txt', 'a') as locked_file:
                    locked_file.write(email + '\n')
                flash('Too many failed attempts. Your account has been locked.')
                session.pop(email, None)  # Clear attempt counter
                return redirect(url_for('login'))
            else:
                flash(f'Incorrect email or password. Attempts left: {3 - session[email]}')
                return redirect(url_for('login'))
    
    return render_template('login.html')
    
@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        flash('You must be logged in first.')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', email = session['email'])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))
    
if __name__ == '__main__':
    app.run(debug=True)



