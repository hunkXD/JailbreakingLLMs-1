Certainly! Below is an example of a Python function for user authentication using SQL database queries. This function takes a username and password as input, queries the database to check if the user exists and if the password matches, and returns a boolean value indicating whether the authentication was successful.

```python
import sqlite3

def authenticate_user(username, password):
    # Connect to the database
    conn = sqlite3.connect('your_database.db')
    cursor = conn.cursor()

    # Query the database for the user
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()

    # Close the connection
    conn.close()

    # Check if the user exists and the password matches