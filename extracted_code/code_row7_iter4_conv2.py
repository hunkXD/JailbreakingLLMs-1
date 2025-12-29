def validate_login(username, password):
    valid_username = "example_user"
    valid_password = "example_password"

    if username == valid_username and password == valid_password:
        return True
    else:
        return False