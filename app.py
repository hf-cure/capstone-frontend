from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
import secrets
import os
import requests
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)


# Initialize database
def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, salt TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY, user_id INTEGER, website TEXT, 
                 username TEXT, password_hash TEXT, salt TEXT)''')
    conn.commit()
    conn.close()


init_db()


# # Password hashing
# def hash_password(password, salt):
#     return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    return redirect('/home')


@app.route('/send_get', methods=['GET'])
def send_get():
    url = "https://jsonplaceholder.typicode.com/posts"  # Example URL
    params = request.args  # Get query parameters
    response = requests.get(url, params=params)
    logging.info(f"GET Response: {response.status_code}, {response.text}")
    return jsonify(response.json()), response.status_code


# Add this new route to app.py
@app.route('/send_entry_o/<int:entry_id>/', methods=['GET'])
def send_entry_0(entry_id):
    # if 'user_id' not in session:
    #     return redirect('/login')

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''SELECT website, username, password_hash, salt 
                 FROM passwords WHERE id=? AND user_id=?''',
              (entry_id, session['user_id']))
    entry = c.fetchone()
    conn.close()

    # return f"Entry ID: {entry}"

    if entry:
        # Prepare data to send
        data = {
            'website': entry[0],
            'username': entry[1],
            'password_hash': entry[2],
            'salt': entry[3]
        }

        # Send to backend server (replace with your actual backend URL)
        # backend_url = "http://localhost:8000/get/process_strings"
        backend_url = "http://localhost:8000/items/2/"
        # backend_url = "http://127.0.0.1:8000/"
        try:
            response = requests.get(backend_url, json=data)
            if response.status_code == 200:

                print(response)
                flash(f"Successfully sent {entry[0]} credentials to backend")
            else:
                flash("Failed to send to backend")
        except requests.RequestException:
            flash("Error connecting to backend server")

    return redirect('/home')


@app.route('/send_entry1/<int:entry_id>', methods=['POST'])
def send_entry1(entry_id):
    if 'user_id' not in session:
        flash("Unauthorized")
        return redirect('/login')

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''SELECT website, username, password_hash, salt 
                 FROM passwords WHERE id=? AND user_id=?''',
              (entry_id, session['user_id']))
    entry = c.fetchone()
    conn.close()

    if entry:
        data = {
            'website': entry[0],
            'username': entry[1],
            'password_hash': entry[2],
            'salt': entry[3]
        }

        backend_url = "http://127.0.0.1:8000/items/"
        try:
            response = requests.post(backend_url, json=data)
            if response.status_code == 200:
                # OLD FLASH MESSAGE
                # flash(f"Sent {response.text} to backend!")
                # flash(f"Sent {entry[0]} to backend!")

                result = response.json()
                if result.get('matched'):  # If 'matched' list is not empty
                    flash("Password Insecure", "danger")  # RED banner
                else:
                    flash("Password Secure", "success")  # GREEN banner

            else:
                flash(f"Backend error: {response.text}", "danger")
        except requests.RequestException as e:
            flash(f"Failed to connect: {str(e)}", "danger")

    return redirect('/home')  # Redirect AFTER sending

@app.route('/send_entry/<int:entry_id>', methods=['POST'])
def send_entry(entry_id):
    if 'user_id' not in session:
        flash("Unauthorized", "danger")
        return redirect('/login')

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''SELECT website, username, password_hash, salt 
                 FROM passwords WHERE id=? AND user_id=?''',
              (entry_id, session['user_id']))
    entry = c.fetchone()
    conn.close()

    if entry:
        data = {
            'website': entry[0],
            'username': entry[1],
            'password_hash': entry[2],
            'salt': entry[3]
        }

        backend_url = "http://127.0.0.1:8000/items/"
        try:
            response = requests.post(backend_url, json=data)
            if response.status_code == 200:
                resp_json = response.json()
                if 'matched' in resp_json and len(resp_json['matched']) > 0:
                    session[f'status_{entry_id}'] = 'insecure'
                else:
                    session[f'status_{entry_id}'] = 'secure'
            else:
                flash("Backend error", "danger")
        except requests.RequestException as e:
            flash(f"Failed to connect: {str(e)}", "danger")

    return redirect('/home')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('SELECT id, password_hash, salt FROM users WHERE username=?', (username,))
        user = c.fetchone()
        conn.close()

        # if user and hash_password(password, user[2]) == user[1]:
        if user and hash_password(password) == user[1]:
            session['user_id'] = user[0]
            return redirect('/home')
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        salt = secrets.token_hex(16)
        password_hash = hash_password(password)

        try:
            conn = sqlite3.connect('passwords.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password_hash, salt) VALUES (?,?,?)',
                      (username, password_hash, salt))
            conn.commit()
            conn.close()
            flash('Account created! Please login')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('Username exists')
    return render_template('signup.html')


@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''SELECT website, username, password_hash, id 
                 FROM passwords WHERE user_id=?''',
              (session['user_id'],))
    passwords = c.fetchall()
    conn.close()

    # Mask the password with 10 asterisks
    masked_passwords = []
    for website, username, password_hash, id_ in passwords:
        masked_passwords.append((website, username, "**", id_))

    return render_template('home.html', passwords=masked_passwords)


@app.route('/reset_security_status', methods=['POST'])
def reset_security_status():
    """
    Reset the security status of all passwords to 'unknown'
    by removing the status_[id] keys from the session.
    """
    if 'user_id' not in session:
        flash("Unauthorized", "danger")
        return redirect('/login')

    # Get all password entries for the user
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute(
        'SELECT id FROM passwords WHERE user_id = ?',
        (session['user_id'],)
    )
    password_entries = c.fetchall()
    conn.close()

    # Remove status_[id] keys from session
    for (id_,) in password_entries:
        if f'status_{id_}' in session:
            session.pop(f'status_{id_}')

    # Ensure session is saved
    session.modified = True

    # Show success message
    flash('All password security statuses have been reset', 'success')

    return redirect('/home')

@app.route('/add', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        
        # Check for existing entry
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('''SELECT id FROM passwords 
                     WHERE user_id=? AND website=? AND username=?''',
                  (session['user_id'], website, username))
        existing = c.fetchone()
        
        if existing:
            conn.close()
            flash('This website/username combination already exists!', 'danger')
            return render_template('add_password.html')
        
        # If not existing, proceed with creation
        salt = secrets.token_hex(16)
        password_hash = hash_password(password)
        
        try:
            c.execute('''INSERT INTO passwords 
                         (user_id, website, username, password_hash, salt) 
                         VALUES (?,?,?,?,?)''',
                      (session['user_id'], website, username, password_hash, salt))
            conn.commit()
            flash('Password added successfully!', 'success')
        except Exception as e:
            conn.rollback()
            flash('Failed to add password', 'danger')
            app.logger.error(f"Error adding password: {str(e)}")
        finally:
            conn.close()
        
        return redirect('/home')

    return render_template('add_password.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/login')



@app.route('/edit/<int:entry_id>', methods=['GET'])
def edit_password(entry_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''SELECT id, website, username FROM passwords 
                 WHERE id=? AND user_id=?''', (entry_id, session['user_id']))
    password = c.fetchone()
    conn.close()

    if not password:
        flash('Password entry not found', 'danger')
        return redirect('/home')

    return render_template('edit_password.html', password={
        'id': password[0],
        'website': password[1],
        'username': password[2]
    })

@app.route('/update/<int:entry_id>', methods=['POST'])
def update_password(entry_id):
    if 'user_id' not in session:
        return redirect('/login')

    if not request.form.get('password'):
        flash('Password cannot be empty', 'danger')
        return redirect(f'/edit/{entry_id}')

    new_website = request.form['website']
    new_username = request.form['username']
    new_password = request.form['password']
    
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    try:
        # Check if the new website/username exists for another entry
        c.execute('''SELECT id FROM passwords 
                     WHERE user_id=? AND website=? AND username=? AND id!=?''',
                  (session['user_id'], new_website, new_username, entry_id))
        duplicate = c.fetchone()
        
        if duplicate:
            flash(f'The combination of {new_website} and {new_username} already exists for another entry!', 'danger')
            return redirect(f'/edit/{entry_id}')
        
        # If no duplicate, proceed with update
        password_hash = hash_password(new_password)
        
        c.execute('''UPDATE passwords 
                     SET password_hash=?, username=?, website=?
                     WHERE id=? AND user_id=?''',
                  (password_hash, new_username, new_website, entry_id, session['user_id']))
        conn.commit()
        flash('Password updated successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash('Failed to update password', 'danger')
        app.logger.error(f"Error updating password: {str(e)}")
    finally:
        conn.close()

    return redirect('/home')

@app.route('/delete_password/<int:entry_id>', methods=['POST'])
def delete_password(entry_id):
    if 'user_id' not in session:
        flash('Unauthorized', 'danger')
        return redirect('/login')

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    try:
        # Delete the password entry
        c.execute('''DELETE FROM passwords 
                     WHERE id=? AND user_id=?''',
                  (entry_id, session['user_id']))
        
        # Remove its security status from session if exists
        if f'status_{entry_id}' in session:
            session.pop(f'status_{entry_id}')
            
        conn.commit()
        flash('Password deleted successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash('Failed to delete password', 'danger')
        app.logger.error(f"Error deleting password: {str(e)}")
    finally:
        conn.close()

    return redirect('/home')


if __name__ == '__main__':
    app.run(debug=True)