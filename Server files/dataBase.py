import sqlite3
from datetime import datetime

DATABASE_NAME = 'defensive.db'

def setup_database():
    """
    Initializes the SQLite database and creates necessary tables if they don't exist.
    This function sets up the structure for storing client information and file records.
    It's called when the server starts to ensure the database is ready for use.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS clients
                 (id BLOB PRIMARY KEY, name TEXT UNIQUE, public_key BLOB, last_seen TEXT, aes_key BLOB)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id BLOB, file_name TEXT, path_name TEXT, verified INTEGER, 
                  PRIMARY KEY (id, file_name))''')
    conn.commit()
    conn.close()

def get_client(client_id):
    """
    Retrieves all information about a specific client from the database.
    This is used to verify client identity and retrieve necessary information
    for handling client requests and file operations.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE id = ?", (client_id,))
    client = c.fetchone()
    conn.close()
    return client

def get_client_by_name(name):
    """
    Searches for a client in the database using their username.
    This is particularly useful during the registration process to check
    if a username is already taken.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE name = ?", (name,))
    client = c.fetchone()
    conn.close()
    return client

def add_client(client_id, name, aes_key):
    """
    Adds a new client to the database. This function is called when a new client
    successfully registers with the server. It stores the client's ID, username,
    and initial AES key.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO clients (id, name, last_seen, aes_key) VALUES (?, ?, ?, ?)",
                  (client_id, name, datetime.now().isoformat(), aes_key))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False
    conn.close()
    return True

def update_client_key(client_id, public_key):
    """
    Updates a client's public key in the database. This is typically called
    when a client reconnects or updates their encryption keys. It also updates
    the 'last_seen' timestamp for the client.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute("UPDATE clients SET public_key = ?, last_seen = ? WHERE id = ?",
              (public_key, datetime.now().isoformat(), client_id))
    conn.commit()
    conn.close()

def get_client_aes_key(client_id):
    """
    Retrieves the AES key associated with a specific client. This key is used
    for encrypting and decrypting data exchanged with the client.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute("SELECT aes_key FROM clients WHERE id = ?", (client_id,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def add_file(client_id, file_name, path_name, verified):
    """
    Adds or updates a file record in the database. This is called when a client
    uploads a file or when the status of a file changes (e.g., when it's verified).
    """
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO files (id, file_name, path_name, verified) VALUES (?, ?, ?, ?)",
              (client_id, file_name, path_name, verified))
    conn.commit()
    conn.close()

def get_file(client_id, file_name):
    """
    Retrieves information about a specific file associated with a client.
    This can be used to check if a file exists, its verification status, or its storage path.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE id = ? AND file_name = ?", (client_id, file_name))
    file = c.fetchone()
    conn.close()
    return file