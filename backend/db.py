import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            autocommit=False,
            connection_timeout=5,
            charset="utf8mb4",
            collation="utf8mb4_unicode_ci"
        )
    except mysql.connector.Error as err:
        # Controlled failure – don't leak credentials
        raise RuntimeError("Database connection failed") from err
