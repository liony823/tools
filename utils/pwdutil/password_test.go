package pwdutil

import "testing"

func TestPasswordIsMatch(t *testing.T) {
	password := "12345"
	isMatch := CheckPassword(password)
	if !isMatch {
		t.Fatalf("Expected true, got %v", isMatch)
	}
}

func TestPasswordEncrypt(t *testing.T) {
	password := "123456"
	hashedPassword, err := EncryptPassword(password)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	isMatch := VerifyPassword(password, hashedPassword)
	if !isMatch {
		t.Fatalf("Expected true, got %v", isMatch)
	}
}
