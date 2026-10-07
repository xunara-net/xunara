package state

import (
	"slices"
	"strings"
	"testing"
)

func TestNormalizeTags(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "empty", in: nil, want: nil},
		{name: "blank entries are dropped", in: []string{"", "  "}, want: nil},
		{
			name: "sorted and deduplicated",
			in:   []string{"tag:prod", "tag:server", "tag:prod"},
			want: []string{"tag:prod", "tag:server"},
		},
		{name: "whitespace is trimmed", in: []string{" tag:prod "}, want: []string{"tag:prod"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeTags(tt.in)
			if err != nil {
				t.Fatalf("NormalizeTags(%v): %v", tt.in, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("NormalizeTags(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeTagsRejectsBadInput(t *testing.T) {
	bad := [][]string{
		{"prod"},           // missing the tag: prefix
		{"tag:"},           // empty name
		{"tag:1prod"},      // must start with a letter
		{"tag:with space"}, // illegal character
		{"tag:" + strings.Repeat("a", maxTagNameLength)}, // too long
	}
	for _, in := range bad {
		if got, err := NormalizeTags(in); err == nil {
			t.Errorf("NormalizeTags(%v) = %v, want an error", in, got)
		}
	}
}
