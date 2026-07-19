import sqlite3

DATABASE = "threatintel.db"


def get_connection():
    return sqlite3.connect(DATABASE)

def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_value TEXT NOT NULL,
        ioc_type TEXT,
        risk_score REAL,
        risk_level TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

# Create a new user
def create_user(username, password_hash):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO users (username, password_hash)
        VALUES (?, ?)
        """,
        (username, password_hash)
    )

    conn.commit()
    conn.close()

# Get user information for login
def get_user(username):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, username, password_hash
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()

    conn.close()

    return user


# Save IOC investigation result
def save_ioc(ioc_value, ioc_type, risk_score, risk_level):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO iocs 
        (ioc_value, ioc_type, risk_score, risk_level)
        VALUES (?, ?, ?, ?)
        """,
        (
            ioc_value,
            ioc_type,
            risk_score,
            risk_level
        )
    )

    conn.commit()
    conn.close()
