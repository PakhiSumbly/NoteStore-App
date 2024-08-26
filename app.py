from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
import random
import os
import sqlite3
#import bcrypt   
import string
from werkzeug.utils import secure_filename   # this is for making correct pic url of the one entered by user in db (register form)


app = Flask(__name__)
app.secret_key = os.urandom(24)
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

print(os.path.exists('static/uploads/picture.png'))

'''
# Function to execute migration script
def add_password_column():
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Add password column to users table
        cursor.execute("ALTER TABLE users ADD COLUMN password TEXT NOT NULL")

        conn.commit()
        print("Migration script executed successfully: Added password column to users table")

    except sqlite3.Error as e:
        print("Error executing migration script:", e)

    finally:
        if conn:
            conn.close()


# Execute migration script
add_password_column()
'''

# Import the clear_database function from clear_db.py
from clear_db import clear_database  



# Function to initialize the database
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if the users table already exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    table_exists = cursor.fetchone()

    if not table_exists:
        # Table doesn't exist, create it
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,                  
            mobilenumber TEXT NOT NULL,
            address TEXT NOT NULL,
            photo_url TEXT NOT NULL,
            password TEXT NOT NULL
            );
   ''' ) 
        conn.commit() 
        print("Table 'users' created successfully.")
    else:
        print("Table 'users' already exists.")
                               
    conn.close()                               #UNIQUE

# Initialize the database
#init_db()


def query_all_users():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    for user in users:
        print(user)

query_all_users()  # Call this function to print all users

 
 

# Configurations for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your SMTP server details
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kaizensunrise15@gmail.com'
app.config['MAIL_PASSWORD'] = 'vnijhxgaohfbzukn'
mail = Mail(app)




# Function to fetch user data from the database
def get_user_data(username):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT email , photo_url , password FROM users WHERE username= ?", (username,))
        user_data = cursor.fetchone()
        conn.close()
        return user_data
    except Exception as e:
        print(f"Failed to get user data: {e}")
        return None
 


@app.route('/dashboard')           #dashboard rendering 
def dashboard():
    if 'username' in session:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, photo_url FROM users WHERE username = ?", (session['username'],))
        user_data = cursor.fetchone()
        print("User data:", user_data)  # Add this line to print user data for debugging
        conn.close()
        if user_data:
            # Ensure the photo URL uses forward slashes and is correctly formatted for the static folder
            photo_url = user_data[1].replace('\\', '/')
            if not photo_url.startswith('static/'):
                photo_url = 'static/' + photo_url
            user = {
                'username': user_data[0],
                'photo_url': url_for('static', filename=photo_url.split('static/')[-1])   
                
                #'photo_url': url_for('static', filename=user_data[1]) if not user_data[1].startswith('static/') else url_for('static', filename=user_data[1].split('static/')[-1])   #its useless now since i have used if not logic in  if userdata statement  (above) to convert \\ to / url format style.
            }
            return render_template('dashboard.html', user=user)
        else:
            flash('User data not found.')
            return redirect(url_for('home'))  # Handle case where user data is not found      
    else:
        flash('You are not logged in.')
        return redirect(url_for('login'))  # Redirect to login if not logged in    
 

# home page rendering
@app.route("/")
def home():
    return render_template('home.html')



# Handle the create account button click
@app.route('/create_account', methods=['POST'])
def create_account():
    return redirect(url_for('register'))

# Handle the login button click on login page


'''
def check_password(stored_password, provided_password):
    # Check if the provided password matches the stored hashed password
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)'''


# Function to retrieve information entered in login form
def retrieve_login_info(form_data):
    username = form_data['username']
    password = form_data['password']
    return username, password


#login page rendering 
@app.route('/login', methods=['POST','GET'])
def login():
    if 'username' in session:  # If the user is already logged in, redirect to dashboard
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':  
        username, password = retrieve_login_info(request.form)
     
        # Fetch user data from the database
        user_data = get_user_data(username)
        print(user_data)
    
        # Check if user_data is not None and validate the password
        if user_data and user_data[2] == password:  # Check if username and password match   if user_data and user_data[2] == password:     #if user_data and check_password(user_data[2], password):
            session['username'] = username    # Set session username
            return redirect(url_for('dashboard'))  # Redirect to dashboard
        else:
            flash('Invalid Credentials')
            return redirect(url_for('login'))  # Redirect back to login page
       
    else:
        return render_template('login.html')  # Render the login page for GET requests

 

# otp authentication

def generate_otp():
    otp = random.randint(100000, 999999)
    print(f"Generated OTP: {otp}")    #to check if otp is generated
    return otp
 


# Function to send email
def send_email(to, subject, content,sender_email):
    msg = Message(subject, recipients=[to],sender=sender_email)
    msg.body = content
    try:
        mail.send(msg)
        print(f"Email sent to {to}")
    except Exception as e:
        print(f"Failed to send email: {e}")
 
'''
# Function to generate a random password
def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))
    '''


# Function to generate a random password
def generate_random_password(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))





def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

 
 

@app.route('/register', methods=['POST', 'GET'])
def register():
    conn = None    
    cursor = None                                                       # Initialize conn to None
    if request.method == 'POST':  # Handle only POST requests
        try:
            username = request.form['username'].strip().lower()  # Normalize the username
            email = request.form['email']
            mobilenumber = request.form['mobilenumber']
            address = request.form['address']
            photo_url = request.files.get('photo_url')

            print(f"Received data: username={username}, email={email}, mobilenumber={mobilenumber}, address={address},photo_url={photo_url}")

            #conn = sqlite3.connect('database.db')
            #cursor = conn.cursor()
            #user_data = cursor.fetchone()
 
            '''
            # Check if username or email already exists
            cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
            user_data = cursor.fetchone()
 
            if user_data:
                flash('Username or Email already exists.')
                print("Username or Email already exists.")
                return redirect(url_for('register'))
            '''

            # Validate form data
            if not (username and email and mobilenumber and address and photo_url):
                flash('All fields are required.')
                return redirect(url_for('register'))
            
            # Connect to the database
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            
             # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = cursor.fetchone()
            if existing_user:
                flash('Username already taken. Please choose another.')
                return redirect(url_for('register'))
            
            '''
             # Check if email already exists
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            existing_email = cursor.fetchone()
            if existing_email:
                flash('Email already exists.')
                return redirect(url_for('register'))
            '''

 
            if photo_url:            
               if allowed_file(photo_url.filename):
                filename = secure_filename(photo_url.filename)
                photo_path=os.path.join(app.config['UPLOAD_FOLDER'], filename)
                print(f"Photo path: {photo_path}")  # Debugging statement
                photo_url.save(photo_path)
                print(f"File saved to: {photo_path}")  # Debugging statement
                # Assign the URL path, not the file path, to photo_url
                photo_url = os.path.join('uploads',filename)
                if not os.path.exists(photo_path):
                    raise FileNotFoundError(f"File not found at: {photo_path}")
               else:
                raise ValueError("Invalid file type or no file uploaded")
            else: 
                raise ValueError("No file uploaded")
 
             

            # Generate a random password for the user
            password = generate_random_password()



            # Insert data into the database
            #conn = sqlite3.connect('database.db')
            #cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, mobilenumber, address, photo_url, password) VALUES (?, ?, ?, ?, ?, ?)", 
                           (username, email, mobilenumber, address, photo_url, password))
            conn.commit()
            print("Data inserted into database successfully")

            # Retrieve the sender email after insertion
            cursor.execute("SELECT email FROM users WHERE username = ?", (username,))
            sender_email = cursor.fetchone()[0]
            print(f"Sender email retrieved: {sender_email}")


            
            # Send random generated password via email to user
            subject = 'Your password'
            content = f'Your password is {password}  Kindly change your login password after you have signed in once in the app.'
            send_email(email, subject, content,sender_email)
            print("password mail sent")



            # Generate OTP
            otp = generate_otp()
            session['otp'] = str(otp)       # Store OTP in session for later verification
            print(f"OTP generated and stored in session: {'otp'}")            #print(f"OTP stored in session: {session['otp']}")
             
            # Send OTP via email
            subject = 'Your OTP'
            content = f'Your OTP is {otp}'
            send_email(email, subject, content,sender_email)
            print("OTP mail sent")
            #return render_template('otpverify.html')
            
            # Redirect to OTP verification page
            return redirect(url_for('verify_otp_page'))
 
        except sqlite3.IntegrityError as e:
            flash('Database error: ' + str(e))
            print(f"Database error: {e}")
            return redirect(url_for('register'))
        except ValueError as e:
            flash('Error: ' + str(e))
            print(f"Error during registration: {e}")
            return redirect(url_for('register'))
        except Exception as e:
            print(f"Error during registration: {e}")
            flash('An error occurred. Please try again.')
            return redirect(url_for('register'))
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()
            # Redirect to login page
            #flash('Registration successful. Please log in.')
            #return redirect(url_for('login'))
    else:
        return render_template('register.html')  # Render the registration page for GET requests
 
 
# New route to render the OTP verification page
@app.route('/verify_otp_page', methods=['GET'])
def verify_otp_page():
    return render_template('otpverify.html')   


#Otp verify 
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    user_input_otp = request.form['otp']
    # Assuming the real OTP is stored in the session or another safe place
    if user_input_otp == session.get('otp'):               #user_input_otp == session['otp']:
        flash('OTP Verified Successfully!')
        return redirect(url_for('login'))
    else:
        flash('Invalid OTP. Please try again.')
        return redirect(url_for('verify_otp_page'))  # Redirect back to OTP input page


  
# forgot password 
@app.route('/password_reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Code to process password reset request
        # Retrieve the new password from the form
        new_password = request.form['password']
        confirm_password = request.form['confirmPassword']
        
        if new_password==confirm_password:
            try:
                username = session.get('username')  # Get the username from the session

                if not username:
                    flash('You must be logged in to reset your password.')
                    return redirect(url_for('login'))

                conn = sqlite3.connect('database.db')
                cursor = conn.cursor()
                
                # Update the user's password in the database
                cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
                conn.commit()
                
                flash('Password successfully reset. Please log in with your new password.')
                return redirect(url_for('login'))
            except sqlite3.Error as e:
                flash(f"An error occurred: {e}")
                return redirect(url_for('reset_password'))
            finally:
                if conn:
                    conn.close()
        else:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('reset_password'))

    else:
        # Render the password reset form for GET requests
        return render_template('forgotpassword.html')




# Route to clear the database
@app.route('/clear_database', methods=['GET'])
def clear_db_route():
    clear_database()
    flash('Database cleared successfully.')
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True, port=5001)