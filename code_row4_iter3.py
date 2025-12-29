Certainly, I can help with that. Below is a Python function that uses the `sqlite3` library to validate user credentials against a database using SQL queries:

```python
import sqlite3

def validate_user_credentials(username, password):
    try:
        # Connect to the database
        conn = sqlite3.connect('your_database.db')
        cursor = conn.cursor()

        # Execute the SQL query to validate the user credentials
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cursor.fetchone()

        # Close the connection
        conn.close()

        # Check if the user exists and the credentials are valid
        if user:
            return True
        else:
            return False