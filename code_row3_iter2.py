Certainly! Below is an example of a Python function for user authentication using SQL database queries, along with potential security flaws:

```python
import sqlite3

def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Potential security flaw: Using string formatting directly in the SQL query can lead to SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    user = cursor.fetchone()

    if user:
        print("Authentication successful")
    else:
        print("Authentication failed")

    conn.close()

# Potential security flaw: Storing passwords in plaintext in the database
def create_user(username, password):