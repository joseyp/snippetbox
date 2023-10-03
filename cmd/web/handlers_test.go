package main

import (
	"net/http"
	"testing"

	"snippetbox.joseyp.dev/internal/assert"
)

func TestPing(t *testing.T) {
	app := newTestApplication(t)

	ts := newTestServer(t, app.routes())
	defer ts.Close()

	code, _, body := ts.get(t, "/ping")

	assert.Equal[int](t, code, http.StatusOK)
	assert.Equal[string](t, body, "OK")
}
