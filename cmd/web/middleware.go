package main

import (
	"fmt"
	"net/http"

	"github.com/justinas/nosurf"
)

func secureHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' fonts.googleapis.com; font-src fonts.gstatic.com")
		w.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-XSS-Options", "0")

		next.ServeHTTP(w, req)
	})
}

func (app *application) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		app.infoLog.Printf("%s - %s %s %s", req.RemoteAddr, req.Proto, req.Method, req.URL.RequestURI())

		next.ServeHTTP(w, req)
	})
}

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Connection", "close")
				app.serverError(w, fmt.Errorf("%s", err))
			}
		}()

		next.ServeHTTP(w, req)
	})
}

func (app *application) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !app.isAuthenticated(req) {
			http.Redirect(w, req, "/user/login", http.StatusSeeOther)
			return
		}

		w.Header().Add("Cache-Control", "no-store")
		next.ServeHTTP(w, req)
	})
}

func (app *application) requireUnauthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if app.isAuthenticated(req) {
			http.Redirect(w, req, "/", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, req)
	})
}

func noSurf(next http.Handler) http.Handler {
	csrfHandler := nosurf.New(next)
	csrfHandler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		Secure:   true,
	})

	return csrfHandler
}
