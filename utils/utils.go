package utils

import (
	"slices"
	"strings"
)

// Write test for this.
func CleanProfanity(body string) string {
	words := []string{"kerfuffle", "sharbert", "fornax"}
	loweredBody := strings.Split(body, " ")

	for i, word := range loweredBody {
		if slices.Contains(words, strings.ToLower(word)) {
			loweredBody[i] = "****"
		}
	}

	return strings.Join(loweredBody, " ")
}
