def validate_login(username, password):
    # Replace this with your actual user database lookup logic
    valid_users = {
        "user1": "password1",
        "user2": "password2"
    }

    if username in valid_users and valid_users[username] == password:
        return True
    else:
        return False