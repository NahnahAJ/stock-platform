from datetime import timedelta
import os
import time
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import firebase_admin
from firebase_admin import credentials, auth, firestore
import requests
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from login import LoginForm, RegistrationForm
load_dotenv()


FIREBASE_API_KEY = os.getenv('FIREBASE_API_KEY')


# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'nahnah70'  # Change to a strong key
csrf = CSRFProtect(app)


# Initialize Firebase
cred = credentials.Certificate('stock-platform-f50e9-firebase-adminsdk-ni5ii-c2f530dc16.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, uid, email, role):
        self.id = uid
        self.email = email
        self.role = role

    def is_admin(self):
        return self.role == 'admin'


@login_manager.user_loader
def load_user(user_id):
    user_ref = db.collection('users').document(user_id).get()
    if user_ref.exists:
        user_data = user_ref.to_dict()
        print(f"This is the CLASS {user_data}")
        return User(uid=user_id, email=user_data['email'], role=user_data.get('role', 'employee'))
    return None

@app.route('/')
def home():
    return render_template('base.html')

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Hash the password for security
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')

        user_record = auth.create_user(
            email=form.email.data,
            password=form.password.data
        )
        
        # Create a user dictionary
        user_data = {
            'username': form.username.data,
            'email': form.email.data,
            'password': hashed_password,
            'uid': user_record.uid,
            'role': 'employee'
        }

        # Add user data to Firestore
        db.collection('users').document(user_record.uid).set(user_data)

        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        try:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={os.getenv('FIREBASE_API_KEY')}"
            response = requests.post(url, json={
                'email': form.email.data,
                'password': form.password.data,
                'returnSecureToken': True
            })

            response_data = response.json()

            if response.status_code == 200:
                id_token = response_data['idToken']
                
                time.sleep(2)
                decoded_token = auth.verify_id_token(id_token)

                uid = decoded_token['uid']
                email = decoded_token['email']

                user = User(uid=uid, email=email, role='employee')
                login_user(user)

                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash(response_data.get('error', {}).get('message', 'Login failed.'), 'danger')
                
        except Exception as e:
            flash(f"Login failed: {str(e)}", 'danger')

    return render_template('login.html', form=form)

# Route for logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Route for the dashboard (protected route)
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('admin_dashboard.html')

def set_custom_claims(uid, role):
    try:
        # role can be 'admin' or 'employee'
        auth.set_custom_user_claims(uid, {'role': role})
        print(f"Successfully set {role} claim for user {uid}")
    except Exception as e:
        print(f"Error setting custom claims: {str(e)}")


if __name__ == '__main__':
    app.run(debug=True)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(minutes=30)

