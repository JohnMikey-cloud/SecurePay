import bcrypt

MAX_ATTEMPTS = 3

users = {
    "admin": {
        "password": bcrypt.hashpw(
            b"correctPassword",
            bcrypt.gensalt()
        ),
        "failed_attempts": 0,
        "locked": False
    }
}

def validate_input(username, password):
    if not username:
        return False, "Username is required."
    if not password:
        return False, "Password is required."
    if "'" in username or "--" in username or ";" in username or "OR" in username.upper():
        return False, "Invalid characters detected."
    return True, ""

def login(username, password):
    try:
        valid, message = validate_input(username, password)
        if not valid:
            return {
                "success": False,
                "message": message
            }
        
        if username not in users:
            return {
                "success": False,
                "message": "Invalid username or password."
            }
            
        user = users[username]
        
        if user["locked"]:
            return {
                "success": False,
                "message": "Account is locked."
            }
            
        password_match = bcrypt.checkpw(
            password.encode(),
            user["password"]
        )
        
        if password_match:
            user["failed_attempts"] = 0
            return {
                "success": True,
                "message": "Login successful."
            }
        else:
            user["failed_attempts"] += 1
            if user["failed_attempts"] >= MAX_ATTEMPTS:
                user["locked"] = True
                return {
                    "success": False,
                    "message": "Account locked after 3 failed attempts."
                }
            return {
                "success": False,
                "message": "Invalid username or password."
            }
    except Exception:
        return {
            "success": False,
            "message": "An unexpected error occurred."
        }