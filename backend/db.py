import mysql.connector
import os
from dotenv import load_dotenv
from contextlib import contextmanager

load_dotenv()


def get_db_connection():
    """
    Creates and returns a new MySQL database connection.
    Credentials are loaded from environment variables.
    """
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
        # Do NOT leak internal details or credentials
        raise RuntimeError("Database connection failed") from err


@contextmanager
def db_cursor(dictionary=True):
    """
    Context manager for database cursor usage.
    Automatically commits on success and rolls back on failure.
    Ensures cursor and connection are always closed.
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=dictionary)
    try:
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()
