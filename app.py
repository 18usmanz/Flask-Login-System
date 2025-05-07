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

        import sqlite3
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        #check if email already exists
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = c.fetchone()

        if existing_user:
            flash('Email already registered. Please log in!')
            conn.close()
            return redirect(url_for('login'))
        
        #insert new user into database
        c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))

        conn.commit()
        conn.close()

        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Connect to database
        import sqlite3
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Check if email exists and get password + lock status
        c.execute('SELECT password, is_locked FROM users WHERE email = ?', (email,))
        user_data = c.fetchone()

        conn.close()

        if user_data:
            db_password, is_locked = user_data

            if is_locked == 1:
                flash('Your account has been locked due to too many failed login attempts.')
                return redirect(url_for('login'))

            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            if hashed_password == db_password:
                flash('Login successful! Welcome back.')
                session['email'] = email  # Save logged-in user
                session.pop(email, None)  # Reset attempt counter
                return redirect(url_for('dashboard'))
            else:
                # Incorrect password
                session[email] = session.get(email, 0) + 1
                if session[email] >= 3:
                    # Lock the account in database
                    conn = sqlite3.connect('database.db')
                    c = conn.cursor()
                    c.execute('UPDATE users SET is_locked = 1 WHERE email = ?', (email,))
                    conn.commit()
                    conn.close()

                    flash('Too many failed attempts. Your account has been locked.')
                    session.pop(email, None)
                    return redirect(url_for('login'))
                else:
                    flash(f'Incorrect password. Attempts left: {3 - session[email]}')
                    return redirect(url_for('login'))
        else:
            # Email not found
            flash('Email not found. Please sign up first!')
            return redirect(url_for('signup'))
    
    return render_template('login.html')('dashboard.html', email = session['email'])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))
    
if __name__ == '__main__':
    app.run(debug=True)



