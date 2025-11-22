# Filename: app.py
# Location: /project_root/app.py
# Description: Main Flask application file that handles all routes and user authentication

# Import necessary libraries
import os  # For accessing environment variables
from flask import Flask, render_template, redirect, url_for, session, request  # Flask web framework components
import bcrypt  # For secure password hashing (cryptographic library)

# Initialize the Flask application
# __name__ tells Flask where to look for templates and static files
app = Flask(__name__)

# Set a secret key for session management
# This key is used to encrypt session cookies for security
# In production, this should be a long, random string stored in environment variables
app.secret_key = os.environ.get('SECRET_KEY', 'your-default-secret-key-change-this-in-production')

# Simple in-memory user database (dictionary)
# In production, this would be a real database like PostgreSQL or MySQL
# The password 'password' is hashed using bcrypt for security
users = {
    'admin': bcrypt.hashpw('password'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
}


# ROUTE 1: Landing page (Homepage for non-logged-in users)
@app.route('/')  # This decorator maps the URL '/' to this function
def landing():
    """
    Display the landing page.
    If user is already logged in, redirect them to the dashboard.
    If not logged in, show the landing page.
    """
    # Check if 'user' key exists in session (means user is logged in)
    if 'user' in session:
        # User is logged in, send them to their dashboard
        return redirect(url_for('index'))
    else:
        # User is not logged in, show the landing page
        return render_template('landing.html')


# ROUTE 2: Dashboard/Index page (for logged-in users only)
@app.route('/index')
def index():
    """
    Display the main dashboard for logged-in users.
    This is a protected route - only accessible after login.
    """
    # Check if user is logged in by looking for 'user' in session
    if 'user' in session:
        # User is logged in, show the dashboard with their username
        return render_template('index.html', user=session['user'])
    else:
        # User is not logged in, redirect to landing page
        return redirect(url_for('landing'))


# ROUTE 3: About page (accessible to everyone)
@app.route('/about')
def about():
    """
    Display the about page.
    This page is publicly accessible - no login required.
    """
    return render_template('about.html')


# ROUTE 4: Login page and authentication logic
@app.route('/login', methods=['GET', 'POST'])  # Accepts both GET (show form) and POST (submit form)
def login():
    """
    Handle user login.
    GET request: Display the login form
    POST request: Process login credentials
    """
    # Check if form was submitted (POST request)
    if request.method == 'POST':
        # Get username and password from the form
        username = request.form['username']
        password = request.form['password'].encode('utf-8')  # Encode to bytes for bcrypt
        
        # Verify credentials:
        # 1. Check if username exists in our users dictionary
        # 2. Check if provided password matches the hashed password
        if username in users and bcrypt.checkpw(password, users[username].encode('utf-8')):
            # Login successful!
            # Store username in session (this keeps user logged in)
            session['user'] = username
            # Redirect to dashboard
            return redirect(url_for('index'))
        else:
            # Login failed - show error message
            return render_template('login.html', error='Invalid username or password')
    
    # GET request - just show the login form
    return render_template('login.html')


# ROUTE 5: Registration page for new users
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle new user registration.
    GET request: Display the registration form
    POST request: Create new user account
    """
    # Check if form was submitted
    if request.method == 'POST':
        # Get username and password from form
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        
        # Check if username already exists
        if username in users:
            # Username taken - show error
            return render_template('register.html', error='Username already exists')
        else:
            # Create new user:
            # 1. Hash the password with bcrypt (never store plain text passwords!)
            # 2. Add to our users dictionary
            users[username] = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
            
            # Automatically log in the new user
            session['user'] = username
            
            # Redirect to dashboard
            return redirect(url_for('index'))
    
    # GET request - show registration form
    return render_template('register.html')


# ROUTE 6: Logout functionality
@app.route('/logout')
def logout():
    """
    Log out the current user.
    Removes user information from session.
    """
    # Remove 'user' from session (if it exists)
    # The None prevents errors if 'user' key doesn't exist
    session.pop('user', None)
    
    # Redirect to landing page
    return redirect(url_for('landing'))


# Run the application
if __name__ == '__main__':
    # Only run if this file is executed directly (not imported)
    # debug=True provides helpful error messages during development
    # IMPORTANT: Set debug=False in production for security!
    app.run(debug=True)