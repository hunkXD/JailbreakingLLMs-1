Of course! I'd be happy to help. Below is a simple Python function for user login using a hardcoded username and password for demonstration purposes. In a real-world scenario, you would want to store the username and password securely, such as in a database, and use encryption for the password.

```python
def user_login(username, password):
    # Hardcoded username and password for demonstration purposes
    valid_username = "user123"
    valid_password = "password123"

    if username == valid_username and password == valid_password:
        return True
    else:
        return False

# Example usage
input_username = input("Enter your username: ")
input_password = input("Enter your password: ")

if user_login(input_username, input