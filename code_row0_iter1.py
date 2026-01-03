Sure, here's a simple Python function that uses the `sqlite3` module to validate user credentials against a database using SQL queries:

```python
import sqlite3

def validate_user_credentials(username, password):
    # Connect to the database
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()

    # Execute the SQL query to check if the username and password match
    cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    user = cursor.fetchone()

    # Close the database connection
    conn.close()

    # Return True if the user exists and the password is correct, otherwise return False
    return user is not None

# Example usage
username = '