package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/pigeonhole_protocols/go/services/gemini"
)

func TestOutputResponseRejectsRedirect(t *testing.T) {
	err := outputResponse(&gemini.Response{Status: 30, Meta: "gemini://example.org/next"}, "")
	require.ErrorContains(t, err, "gemini redirect 30")
	require.ErrorContains(t, err, "gemini://example.org/next")
}
