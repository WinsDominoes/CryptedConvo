import mysql.connector.pooling
from src.encryption import HMAC_encryptor
import os

class DatabaseHandler:
    def __init__(self):
        self.config = {
            'host': 'localhost',
            'user': 'root',
            'password': 'password',
            'database': 'data_privacy'
        }
        self.schema_path = '../db/schema.sql'
        self.connection_pool = self._create_pool()
        self.initialize_database()
        self.HMAC = HMAC_encryptor()

    # Initialize connection pool
    def _create_pool(self):
        return mysql.connector.pooling.MySQLConnectionPool(
            pool_name="auth_pool",
            pool_size=5,  # Adjust based on expected concurrent users
            **self.config
        )

    # Get connection from pool
    def get_connection(self):
        return self.connection_pool.get_connection()

    # Create database and tables using pooling
    def initialize_database(self):
        try:
            # Temporary config without database name
            temp_config = self.config.copy()
            temp_config.pop('database')
            
            with mysql.connector.connect(**temp_config) as temp_conn, \
                 temp_conn.cursor() as cursor:
                
                # Create database if not exists
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.config['database']}")
                cursor.execute(f"USE {self.config['database']}")
                
                # Execute schema
                with open(self.schema_path, 'r') as sql_file:
                    cursor.execute(sql_file.read(), multi=True)
                temp_conn.commit()
                
        except Exception as e:
            raise Exception(f"Database init failed: {e}")

    # Securely register user with HMAC hashing
    def register_user(self, username: str, hashed_password: str, salt: bytes) -> bool:
        try:
            with self.get_connection() as conn, conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO users (username, salt, password_hash)
                    VALUES (%s, %s, %s)
                """, (username, salt, hashed_password))
                conn.commit()
                return True
        except mysql.connector.IntegrityError:
            return False  # Username already exists
        except Exception as e:
            print(f"Registration error: {e}")
            return False

    # Verify credentials against stored HMAC hash
    def verify_user(self, username: str, password: str) -> bool:
        try:
            with self.get_connection() as conn, \
                conn.cursor(dictionary=True) as cursor:
                
                cursor.execute("""
                    SELECT salt, password_hash 
                    FROM users 
                    WHERE username = %s
                """, (username,))
                user_data = cursor.fetchone()
                
                if not user_data:
                    return False
                
                return self.HMAC.verify_hash(password, user_data['password_hash'], salt=user_data['salt'])
                
        except Exception as e:
            print(f"Verification error: {e}")
            return False