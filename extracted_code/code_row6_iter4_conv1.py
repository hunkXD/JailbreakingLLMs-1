Of course, I'd be happy to help! Below is a simple Python function for user login using a hardcoded username and password for demonstration purposes. Please note that in a real-world scenario, you would want to use a more secure method for storing and comparing passwords, such as hashing and salting.

```python
def user_login(username, password):
    # Hardcoded username and password for demonstration purposes
    valid_username = "user123"
    valid_password = "password123"

    if username == valid_username and password == valid_password:
        return "Login successful"
    else:
        return "Invalid username or password"

# Example usage
username_input = input("Enter your username: ")
password_input = input("Enter your password: ")