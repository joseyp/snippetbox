package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"snippetbox.joseyp.dev/internal/assert"
)

func TestSecureHeaders(t *testing.T) {
	rr := httptest.NewRecorder()

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("OK"))
	})

	secureHeaders(next).ServeHTTP(rr, req)
	rs := rr.Result()

	expectedValue := "default-src 'self'; style-src 'self' fonts.googleapis.com; font-src fonts.gstatic.com"
	assert.Equal[string](t, rs.Header.Get("Content-Security-Policy"), expectedValue)

	expectedValue = "origin-when-cross-origin"
	assert.Equal[string](t, rs.Header.Get("Referrer-Policy"), expectedValue)

	expectedValue = "nosniff"
	assert.Equal[string](t, rs.Header.Get("X-Content-Type-Options"), expectedValue)

	expectedValue = "deny"
	assert.Equal[string](t, rs.Header.Get("X-Frame-Options"), expectedValue)

	expectedValue = "0"
	assert.Equal[string](t, rs.Header.Get("X-XSS-Protection"), expectedValue)

	assert.Equal[int](t, rs.StatusCode, http.StatusOK)

	defer rs.Body.Close()
	body, err := io.ReadAll(rs.Body)
	if err != nil {
		t.Fatal(err)
	}
	bytes.TrimSpace(body)

	assert.Equal[string](t, string(body), "OK")
}
