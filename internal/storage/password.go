package storage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const passwordIterations = 120000

// hashPassword uses PBKDF2-HMAC-SHA256 with a per-network random salt. The
// format is versioned so the verifier can be upgraded without exposing
// plaintext passwords or silently accepting a weaker new format.
func hashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Sprintf("generate password salt: %v", err))
	}
	derived := pbkdf2SHA256([]byte(password), salt, passwordIterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", passwordIterations,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(derived))
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) == 4 && parts[0] == "pbkdf2-sha256" {
		iterations, err := strconv.Atoi(parts[1])
		salt, saltErr := base64.RawStdEncoding.DecodeString(parts[2])
		expected, expectedErr := base64.RawStdEncoding.DecodeString(parts[3])
		if err != nil || saltErr != nil || expectedErr != nil || iterations < 100000 || iterations > 1000000 || len(salt) < 16 || len(expected) != 32 {
			return false
		}
		actual := pbkdf2SHA256([]byte(password), salt, iterations, len(expected))
		return subtle.ConstantTimeCompare(actual, expected) == 1
	}
	// Accept the first development format so existing local state can be
	// migrated by recreating the network. New networks never use this path.
	sum := sha256.Sum256([]byte(password))
	legacy := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(legacy), []byte(encoded)) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	result := make([]byte, 0, keyLen)
	for block := byte(1); len(result) < keyLen; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{0, 0, 0, block})
		u := mac.Sum(nil)
		f := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range f {
				f[j] ^= u[j]
			}
		}
		result = append(result, f...)
	}
	return result[:keyLen]
}
