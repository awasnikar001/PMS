#!/usr/bin/env python
# coding: utf-8

# In[1]:


#Support generation of password
import hashlib
import random
import string

# Constants
SALT_LENGTH = 16
HASH_ITERATIONS = 100000
MIN_LENGTH = 8
REQUIRED_CHARS = string.ascii_letters + string.digits

def generate_salt():
    """Generates a random salt for password hashing"""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(SALT_LENGTH))

def hash_password(password, salt):
    """Hashes the password using PBKDF2"""
    hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), HASH_ITERATIONS)
    return hash.hex()

def check_password_policy(password):
    """Checks if the password meets the password policy"""
    if len(password) < MIN_LENGTH:
        return False

    has_required_char = False
    for char in REQUIRED_CHARS:
        if char in password:
            has_required_char = True
            break

    return has_required_char

def generate_password():
    """Generates a password that meets the password policy"""
    while True:
        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(MIN_LENGTH))
        if check_password_policy(password):
            return password

def store_password(username, password=None):
    """Stores the hashed password in the database"""
    if password is None:
        password = generate_password()

    if not check_password_policy(password):
        raise ValueError("Password does not meet the password policy")

    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    # Store the username, salt, and hashed password in the database
    # ...

def authenticate(username, password):
    """Authenticates the user using the entered password"""
    # Retrieve the salt and hashed password from the database for the given user
    # ...
    hashed_password_from_db = ...
    salt = ...

    # Hash the entered password using the salt from the database
    entered_hashed_password = hash_password(password, salt)

    # Compare the entered hashed password with the one stored in the database
    if entered_hashed_password == hashed_password_from_db:
        return True
    else:
        return False


# In[ ]:


#According to configurable password policy
import re

class PasswordPolicy:
    def __init__(self, min_length, max_length, min_upper, min_lower, min_digits, min_special):
        self.min_length = min_length
        self.max_length = max_length
        self.min_upper = min_upper
        self.min_lower = min_lower
        self.min_digits = min_digits
        self.min_special = min_special
    
    def validate(self, password):
        if len(password) < self.min_length or len(password) > self.max_length:
            return False
        
        upper_count = 0
        lower_count = 0
        digit_count = 0
        special_count = 0
        for char in password:
            if char.isupper():
                upper_count += 1
            elif char.islower():
                lower_count += 1
            elif char.isdigit():
                digit_count += 1
            elif re.match(r'[!@#$%^&*(),.?":{}|<>]', char):
                special_count += 1
        
        if upper_count < self.min_upper or lower_count < self.min_lower or digit_count < self.min_digits or special_count < self.min_special:
            return False
        
        return True

class PasswordManagementSystem:
    def __init__(self, password_policy):
        self.password_policy = password_policy
        self.passwords = {}
    
    def add_user(self, username, password):
        if not self.password_policy.validate(password):
            return False
        self.passwords[username] = password
        return True
    
    def update_password(self, username, password):
        if not self.password_policy.validate(password):
            return False
        self.passwords[username] = password
        return True

policy = PasswordPolicy(8, 32, 1, 1, 1, 1)
pms = PasswordManagementSystem(policy)
pms.add_user("user1", "password123") # True
pms.add_user("user2", "Password") # False
pms.update_password("user1", "new_password123!") # True


# In[ ]:


#force renewal of existing passwords in case of policy configuration changes
import hashlib
import datetime

# Constants
MIN_LENGTH = 8
MAX_LENGTH = 16
HASH_ALGORITHM = "sha256"

# Dictionary to store users and their passwords
user_passwords = {}

# Function to hash a password using the SHA256 algorithm
def hash_password(password):
    hash_object = hashlib.sha256(password.encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig

# Function to verify if a password meets the policy requirements
def is_password_valid(password, policy):
    if len(password) < policy["min_length"]:
        return False
    if len(password) > policy["max_length"]:
        return False
    return True

# Function to change a user's password
def change_password(username, password, policy):
    if not is_password_valid(password, policy):
        return False
    user_passwords[username] = {"hash": hash_password(password), "timestamp": datetime.datetime.now()}
    return True

# Function to check if a user's password needs to be renewed based on the policy configuration changes
def check_password_renewal(username, policy):
    user = user_passwords.get(username)
    if user is None:
        return False
    elapsed_time = datetime.datetime.now() - user["timestamp"]
    if elapsed_time.days > policy["max_age_days"]:
        return True
    return False

# Example usage
policy = {
    "min_length": MIN_LENGTH,
    "max_length": MAX_LENGTH,
    "max_age_days": 90
}

# Add a new user to the system
username = "johndoe"
password = "secret123"
if change_password(username, password, policy):
    print("Password change successful")
else:
    print("Password change failed, policy requirements not met")

# Check if the user's password needs to be renewed
if check_password_renewal(username, policy):
    print("Password renewal required")
    password = "secret456"
    if change_password(username, password, policy):
        print("Password renewal successful")
    else:
        print("Password renewal failed, policy requirements not met")
else:
    print("Password renewal not required")


# In[ ]:


#storage of passwords 
import bcrypt

# Hash a password for the first time
password = b"supersecretpassword"
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password, salt)

# Check that a unhashed password matches one that has previously been hashed
if bcrypt.checkpw(password, hashed):
    print("Password matches.")
else:
    print("Password does not match.")

# Store the hashed password in the database
# This example uses a SQLite database, but you could use any database of your choice
import sqlite3

conn = sqlite3.connect("passwords.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password BLOB)")
cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("johndoe", hashed))
conn.commit()

# Retrieve the hashed password from the database and check it against a candidate password
cursor.execute("SELECT password FROM users WHERE username=?", ("johndoe",))
stored_password = cursor.fetchone()[0]
candidate_password = b"supersecretpassword"
if bcrypt.checkpw(candidate_password, stored_password):
    print("Password matches.")
else:
    print("Password does not match.")

conn.close()


# In[ ]:


#Evaluate Passwords as part of an authentication process
import bcrypt

def validate_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def authenticate_user(username, password):
    # Connect to the database to retrieve hashed password for the given username
    hashed_password = # Retrieve hashed password from database

    if hashed_password is None:
        return False

    return validate_password(password, hashed_password)

# Example usage:
username = input("Enter username: ")
password = input("Enter password: ")

if authenticate_user(username, password):
    print("Authentication successful.")
else:
    print("Authentication failed.")


# In[ ]:


# Services must be made available via REST/JSON API calls
import bcrypt
import flask
import flask_restful
import json

app = flask.Flask(__name__)
api = flask_restful.Api(app)

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

users = {}

class CreateUser(flask_restful.Resource):
    def post(self):
        data = json.loads(flask.request.data.decode('utf-8'))
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return {'error': 'username and password are required'}, 400
        if username in users:
            return {'error': 'user already exists'}, 400
        user = User(username, password)
        users[username] = user
        return {'message': 'user created'}, 201

class AuthenticateUser(flask_restful.Resource):
    def post(self):
        data = json.loads(flask.request.data.decode('utf-8'))
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return {'error': 'username and password are required'}, 400
        user = users.get(username)
        if not user:
            return {'error': 'user not found'}, 400
        if not bcrypt.checkpw(password.encode('utf-8'), user.password):
            return {'error': 'incorrect password'}, 400
        return {'message': 'authentication successful'}, 200

api.add_resource(CreateUser, '/create')
api.add_resource(AuthenticateUser, '/authenticate')

if __name__ == '__main__':
    app.run()


# In[ ]:


#The System must use an external pwned password service
import hashlib
import requests

class PasswordManagementSystem:
    def __init__(self):
        self.pwned_password_service_url = "https://api.pwnedpasswords.com/range/"
    
    def evaluate_password(self, password):
        """
        Evaluates a password by checking if it has been pwned using the pwned password service.
        """
        # Hash the password using SHA-1
        password_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        # Send the first 5 characters of the hash to the pwned password service
        response = requests.get(f"{self.pwned_password_service_url}{password_hash[:5]}")
        # Check if the full hash appears in the response from the pwned password service
        if password_hash[5:] in response.text:
            return False
        return True

# Example usage
pms = PasswordManagementSystem()
password = "password123"
if pms.evaluate_password(password):
    print(f"Password {password} is safe to use.")
else:
    print(f"Password {password} has been pwned. Please choose a different password.")

