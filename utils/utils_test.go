package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCleanProfanity(t *testing.T) {
	tests := map[string]struct {
		input  string
		output string
	}{
		"clean": {
			input:  "I had something interesting for breakfast",
			output: "I had something interesting for breakfast",
		},
		"dirty": {
			input:  "I hear Mastodon is better than Chirpy. sharbert I need to migrate",
			output: "I hear Mastodon is better than Chirpy. **** I need to migrate",
		},
		"multiple": {
			input:  "I really need a kerfuffle to go to bed sooner, Fornax !",
			output: "I really need a **** to go to bed sooner, **** !",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := CleanProfanity(test.input)
			assert.Equal(t, test.output, result)
		})
	}
}
