// Package validate wraps go-playground/validator with injection-safe custom rules.
// Tests are in validate_test.go (standard Go layout: code vs _test.go).
package validate

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
)

var v = validator.New()

var ErrValidation = fmt.Errorf("validation failed")

// encodedInjectionHints blocks common command-injection strings (defense in depth; no shell is invoked).
var encodedInjectionHints = []string{
	"%3b", "%7c", "%26", "%60", "%24", "%28", "%29",
	"$(", "${", "`", "eval(", "exec(", "system(",
	"/bin/sh", "/bin/bash", "cmd.exe", "powershell",
}

func init() {
	_ = v.RegisterValidation("safe_text", func(fl validator.FieldLevel) bool {
		return IsSafeText(fl.Field().String())
	})
	_ = v.RegisterValidation("safe_password", func(fl validator.FieldLevel) bool {
		return IsSafePassword(fl.Field().String())
	})
}

// Struct runs validation tags on a DTO.
func Struct(s any) error {
	if err := v.Struct(s); err != nil {
		return fmt.Errorf("%w: %s", ErrValidation, err.Error())
	}
	return nil
}

// IsSafeText rejects control characters, shell metacharacters, and encoded injection hints.
func IsSafeText(s string) bool {
	if s == "" || hasDisallowedControl(s) {
		return false
	}
	return !containsShellMeta(s) && !containsEncodedInjectionHint(s)
}

// IsSafePassword allows symbols in passwords but blocks nulls and newlines.
func IsSafePassword(s string) bool {
	if strings.IndexByte(s, 0) >= 0 {
		return false
	}
	for _, r := range s {
		if r == '\n' || r == '\r' {
			return false
		}
	}
	return true
}

// SanitizeLogValue strips control characters and caps length for audit / log fields.
func SanitizeLogValue(s string, maxLen int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, s)
	if maxLen > 0 && len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

func hasDisallowedControl(s string) bool {
	for _, r := range s {
		if r < 32 && r != '\t' {
			return true
		}
		if r == 127 {
			return true
		}
	}
	return strings.IndexByte(s, 0) >= 0
}

func containsShellMeta(s string) bool {
	return strings.ContainsAny(s, "|&;`$()<>\"'\\\n\r")
}

func containsEncodedInjectionHint(s string) bool {
	lower := strings.ToLower(s)
	for _, hint := range encodedInjectionHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}
