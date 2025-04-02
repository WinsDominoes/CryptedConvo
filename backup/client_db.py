from mysql import connector
import hashlib
import hmac
import os
from dotenv import load_dotenv

# Load secret key from .env
load_dotenv()
SECRET_KEY = bytes.fromhex(os.getenv("SECRET_KEY"))

# MySQL configurations
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'password',
    'database': 'data_privacy'
}

def connect_db():
    return connector.connect(**db_config)

def register_user():
    username = input("Enter username: ")
    password = input("Enter password: ")

    conn = connect_db()
    cursor = conn.cursor()
    
    salt = os.urandom(16)
    password_hash = hmac.new(SECRET_KEY, salt + password.encode(), hashlib.sha256).hexdigest()

    query = "INSERT INTO users (username, salt, password_hash) VALUES (%s, %s, %s)"
    cursor.execute(query, (username, salt.hex(), password_hash))
    conn.commit()

    cursor.close()
    conn.close()
    print("User registered successfully.")

def login_user():
    username = input("Enter username: ")
    password = input("Enter password: ")

    conn = connect_db()
    cursor = conn.cursor()

    query = "SELECT salt, password_hash FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user:
        salt = bytes.fromhex(user[0])
        stored_password_hash = user[1]
        computed_hash = hmac.new(SECRET_KEY, salt + password.encode(), hashlib.sha256).hexdigest()

        if hmac.compare_digest(computed_hash, stored_password_hash):
            print("Login successful")
            return
    print("Invalid username or password")

if __name__ == "__main__":
    while True:
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            break
        else:
            print("Invalid option. Try again.")