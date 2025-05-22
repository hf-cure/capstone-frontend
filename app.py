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
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, salt TEXT, name TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY, 
                  user_id INTEGER, 
                  website TEXT, 
                  username TEXT, 
                  password_hash TEXT, 
                  salt TEXT,
                  status TEXT CHECK(status IN ('secure', 'insecure', 'unknown')),
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('SELECT id, password_hash, salt, name FROM users WHERE username=?', (username,))
        user = c.fetchone()
        conn.close()

        # if user and hash_password(password, user[2]) == user[1]:
        if user and hash_password(password) == user[1]:
            session['user_id'] = user[0]
            session['name'] = user[3]  # Store user's name in session
            session['username'] = username  # Store username in session as fallback
            return redirect('/home')
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        salt = secrets.token_hex(16)
        password_hash = hash_password(password)

        try:
            conn = sqlite3.connect('passwords.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password_hash, salt, name) VALUES (?,?,?,?)',
                      (username, password_hash, salt, name))
            conn.commit()
            conn.close()
            flash('Account created! Please login')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('Username already exists')
    return render_template('signup.html')


@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    # Query to count the number of passwords by status for the current user
    # Only looking at 'secure' and 'insecure' statuses
    c.execute('''SELECT status, COUNT(*) FROM passwords WHERE user_id=? 
                 AND status IN ('secure', 'insecure') GROUP BY status''', 
              (session['user_id'],))
    status_counts = dict(c.fetchall())
    
    # Initialize counts with default values of 0
    secure_count = status_counts.get('secure', 0)
    insecure_count = status_counts.get('insecure', 0)

    # Fetch passwords for rendering (masked)
    c.execute('''SELECT website, username, password_hash, status, id 
                 FROM passwords WHERE user_id=?''',
              (session['user_id'],))
    passwords = c.fetchall()
    conn.close()

    # Mask the password with asterisks
    masked_passwords = []
    for website, username, password_hash, status, id_ in passwords:
        masked_passwords.append((website, username, "**", status, id_))

    return render_template('home.html', 
                          passwords=masked_passwords,
                          secure_count=secure_count,
                          insecure_count=insecure_count)


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
    

    # Remove status_[id] keys from session
    for (id_,) in password_entries:
        if f'status_{id_}' in session:
            session.pop(f'status_{id_}')

    # Ensure session is saved
    session.modified = True

    # Show success message
    flash('All password security statuses have been reset', 'success')
    c.execute('''UPDATE passwords SET status = 'unknown' WHERE user_id = ?''', (session['user_id'],))
    conn.commit()
    conn.close()

    return redirect('/home')


@app.route('/add', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        status = 'unknown'
        
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
        
        # Prepare data for API call
        data = {
            'website': website,
            'username': username,
            'password_hash': password_hash,
            'salt': salt
        }
        
        backend_url = "http://127.0.0.1:8000/items/"
        try:
            # API call to check if the password is insecure
            response = requests.post(backend_url, json=data)
            if response.status_code == 200:
                resp_json = response.json()
                if 'matched' in resp_json and len(resp_json['matched']) > 0:
                    status = 'insecure'  # Mark as insecure if the password is leaked
                else:
                    status = 'secure'  # Mark as secure if the password is not leaked
            else:
                flash("Backend error while checking password status.", "danger")
                status = 'unknown'  # Fallback in case the API call fails

        except requests.RequestException as e:
            flash(f"Failed to connect to the backend: {str(e)}", "danger")
            status = 'unknown'  # Fallback if there's an issue with the API call
        
        try:
            # Insert password into the database with the determined status
            c.execute('''INSERT INTO passwords 
                         (user_id, website, username, password_hash, salt, status) 
                         VALUES (?,?,?,?,?,?)''',
                      (session['user_id'], website, username, password_hash, salt, status))
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
        
        # Generate salt and hash the new password
        salt = secrets.token_hex(16)  # Generate a new salt for the updated password
        password_hash = hash_password(new_password)
        
        # Prepare data for the API call to check password status
        data = {
            'website': new_website,
            'username': new_username,
            'password_hash': password_hash,
            'salt': salt
        }
        
        backend_url = "http://127.0.0.1:8000/items/"
        status = 'insecure'  # Default status to 'insecure'
        
        try:
            # Make API call to check password status
            response = requests.post(backend_url, json=data)
            if response.status_code == 200:
                resp_json = response.json()
                if 'matched' in resp_json and len(resp_json['matched']) > 0:
                    status = 'insecure'  # Mark as insecure if the password is leaked
                else:
                    status = 'secure'  # Mark as secure if the password is not leaked
            else:
                flash("Backend error while checking password status.", "danger")
                status = 'insecure'  # If there's an error, we assume the password is insecure
        except requests.RequestException as e:
            flash(f"Failed to connect to the backend: {str(e)}", "danger")
            status = 'insecure'  # Fallback if there's an issue with the API call
        
        # Proceed to update the password record in the database with the new hash and status
        c.execute('''UPDATE passwords 
                     SET password_hash=?, salt=?, username=?, website=?, status=? 
                     WHERE id=? AND user_id=?''',
                  (password_hash, salt, new_username, new_website, status, entry_id, session['user_id']))
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

    if entry:
        data = {
            'website': entry[0],
            'username': entry[1],
            'password_hash': entry[2],
            'salt': entry[3]
        }
        
        # return data
        backend_url = "http://127.0.0.1:8000/items/"
        try:
            response = requests.post(backend_url, json=data)

            if response.status_code == 200:
                resp_json = response.json()
                # return resp_json
                if 'matched' in resp_json and len(resp_json['matched']) > 0:
                    # Password is insecure
                    c.execute('''UPDATE passwords SET status = 'insecure' WHERE user_id = ? AND id = ? ''', (session['user_id'], entry_id))
                    conn.commit()
                    session[f'status_{entry_id}'] = 'insecure'
                else:
                    # Password is secure
                    c.execute('''UPDATE passwords SET status = 'secure' WHERE user_id = ? AND id = ? ''', (session['user_id'], entry_id))
                    conn.commit()
                    session[f'status_{entry_id}'] = 'secure'

            else:
                flash("Backend error", "danger")

        except requests.RequestException as e:
            flash(f"Failed to connect: {str(e)}", "danger")

        # Closing the DB connection after updating the password status
        conn.close()

    return redirect('/home')


@app.route('/send_all_items', methods=['POST'])
def send_all_items():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    try:
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('''SELECT id, website, username, password_hash, salt 
                     FROM passwords WHERE user_id=?''',
                  (session['user_id'],))
        items = c.fetchall()

        if not items:
            return jsonify({"status": "error", "message": "No items found"}), 404

        items_data = {
            "items": [
                {
                    "id": item[0],
                    "website": item[1],
                    "username": item[2],
                    "password_hash": item[3],
                    "salt": item[4]
                } for item in items
            ]
        }

        backend_url = "http://localhost:8000/check-items/"
        
        try:
            response = requests.post(backend_url, json=items_data)
            
            if response.status_code == 200:
                response_data = response.json()
                # console.log(response_data)
                
                # app.logger.info(response_data)
                # return response_data
            
                
                # First, mark all passwords as secure
                c.execute('''UPDATE passwords SET status = 'secure' WHERE user_id = ?''', 
                         (session['user_id'],))
                
                # Get the list of matched (insecure) items
                matched_items = response_data.get("matched_items", [])
                
                # return matched_items
                
                # Update the status of matched (insecure) items
                for item in matched_items:
                    # return item['username']
                    c.execute('''UPDATE passwords SET status = 'insecure' WHERE username = ? AND website = ? AND user_id = ?''', 
                        (item['username'], item['website'], session['user_id']))
                
                conn.commit()
                
                # Get updated counts
                c.execute('''SELECT status, COUNT(*) FROM passwords WHERE user_id=? 
                           AND status IN ('secure', 'insecure') GROUP BY status''', 
                          (session['user_id'],))
                status_counts = dict(c.fetchall())
                
                secure_count = status_counts.get('secure', 0)
                insecure_count = status_counts.get('insecure', 0)
                
                conn.close()
                
                
                
                return jsonify({
                    "status": "success",
                    "total_submitted": len(items),
                    "matches_found": len(matched_items),
                    "secure_count": secure_count,
                    "insecure_count": insecure_count,
                    "status_updates": {str(item.get('id')): 'insecure' for item in matched_items}
                })
            else:
                conn.close()
                return jsonify({
                    "status": "error",
                    "message": f"Backend returned status code {response.status_code}"
                }), 500
                
        except requests.RequestException as e:
            conn.close()
            return jsonify({
                "status": "error",
                "message": f"Failed to connect to backend: {str(e)}"
            }), 500

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500



if __name__ == '__main__':
    app.run(debug=True)