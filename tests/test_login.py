from tests.login import login

def test_valid_login():
    result = login("admin", "correctPassword")
    assert result["success"] is True

def test_bad_username():
    result = login("unknown_user", "correctPassword")
    assert result["success"] is False

def test_wrong_password():
    result = login("admin", "wrongPassword")
    assert result["success"] is False

def test_account_lockout():
    login("admin", "wrongPassword")
    login("admin", "wrongPassword")
    login("admin", "wrongPassword")
    result = login("admin", "wrongPassword")
    assert result["success"] is False
    assert "locked" in result["message"].lower()

def test_sql_injection_attempt():
    result = login("' OR '1'='1", "anything")
    assert result["success"] is False

def test_empty_username():
    result = login("", "password")
    assert result["success"] is False
    assert result["message"] == "Username is required."

def test_empty_password():
    result = login("admin", "")
    assert result["success"] is False
    assert result["message"] == "Password is required."

def test_both_fields_blank():
    result = login("", "")
    assert result["success"] is False
    assert result["message"] == "Username is required."

def test_locked_account_blocks_correct_password():
    login("admin", "wrongPassword")
    login("admin", "wrongPassword")
    login("admin", "wrongPassword")
    result = login("admin", "correctPassword")
    assert result["success"] is False
    assert result["message"] == "Account is locked."