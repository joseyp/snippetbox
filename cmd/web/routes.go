package main

import (
	"net/http"

	"snippetbox.joseyp.dev/ui"

	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
)

func (app *application) routes() http.Handler {
	router := httprouter.New()

	router.NotFound = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		app.notFound(w)
	})

	fileServer := http.FileServer(http.FS(ui.Files))
	router.Handler(http.MethodGet, "/static/*filepath", fileServer)

	router.HandlerFunc(http.MethodGet, "/ping", ping)

	dynamic := alice.New(app.sessionManager.LoadAndSave, noSurf, app.authenticate)
	router.Handler(http.MethodGet, "/", dynamic.ThenFunc(app.home))
	router.Handler(http.MethodGet, "/snippet/view/:id", dynamic.ThenFunc(app.snippetView))

	unauthenticated := dynamic.Append(app.requireUnauthentication)
	router.Handler(http.MethodGet, "/user/signup", unauthenticated.ThenFunc(app.userSignup))
	router.Handler(http.MethodPost, "/user/signup", unauthenticated.ThenFunc(app.userSignupPost))
	router.Handler(http.MethodGet, "/user/login", unauthenticated.ThenFunc(app.userLogin))
	router.Handler(http.MethodPost, "/user/login", unauthenticated.ThenFunc(app.userLoginPost))

	authenticated := dynamic.Append(app.requireAuthentication)
	router.Handler(http.MethodGet, "/snippet/create", authenticated.ThenFunc(app.snippetCreate))
	router.Handler(http.MethodPost, "/snippet/create", authenticated.ThenFunc(app.snippetCreatePost))
	router.Handler(http.MethodPost, "/user/logout", authenticated.ThenFunc(app.userLogoutPost))

	standard := alice.New(app.recoverPanic, app.logRequest, secureHeaders)
	return standard.Then(router)
}
