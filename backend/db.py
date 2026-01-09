import mysql.connector
import os
from dotenv import load_dotenv
from contextlib import contextmanager

load_dotenv()

def get_db_connection():
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            port=int(os.getenv("DB_PORT", 3306)),
            autocommit=False,
            connection_timeout=5,
            charset="utf8mb4",
            collation="utf8mb4_bin"
        )
    except mysql.connector.Error as err:
        raise RuntimeError("Database connection failed") from err


@contextmanager
def db_cursor():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()
