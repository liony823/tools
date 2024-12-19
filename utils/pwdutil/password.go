package pwdutil

import (
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

var pwdRegex = regexp.MustCompile(`^[a-zA-Z0-9]{6,18}$`)

// 加密明文密码
func EncryptPassword(password string) (string, error) {
	// 使用 bcrypt 对密码进行哈希
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// 验证密码
func VerifyPassword(password string, hashedPassword string) bool {
	// 比较明文密码与哈希后的密码是否匹配
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// 检查管理员密码格式是否符合pwdRegex
func CheckPassword(password string) bool {
	return pwdRegex.MatchString(password)
}
