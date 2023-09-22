package main

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"
	"snippetbox.joseyp.dev/internal/models"
	"snippetbox.joseyp.dev/internal/validator"
)

type snippetCreateForm struct {
	Title               string `form:"title"`
	Content             string `form:"content"`
	Expires             int    `form:"expires"`
	validator.Validator `form:"-"`
}

type userSignupForm struct {
	Name                string `form:"name"`
	Email               string `form:"email"`
	Password            string `form:"password"`
	validator.Validator `form:"-"`
}

type userLoginForm struct {
	Email               string `form:"email"`
	Password            string `form:"password"`
	validator.Validator `form:"-"`
}

func (app *application) home(w http.ResponseWriter, req *http.Request) {
	snippets, err := app.snippets.Latest()
	if err != nil {
		app.serverError(w, err)
		return
	}

	data := app.newTemplateData(req)
	data.Snippets = snippets

	app.render(w, http.StatusOK, "home.gohtml", data)
}

func (app *application) userSignup(w http.ResponseWriter, req *http.Request) {
	data := app.newTemplateData(req)
	data.Form = userSignupForm{}
	app.render(w, http.StatusOK, "signup.gohtml", data)
}

func (app *application) userSignupPost(w http.ResponseWriter, req *http.Request) {
	var form userSignupForm

	err := app.decodePostForm(req, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form.CheckField(validator.NotBlank(form.Name), "name", "This field cannot be empty")
	form.CheckField(validator.NotBlank(form.Email), "email", "This field cannot be empty")
	form.CheckField(validator.Matches(form.Email, validator.EmailRX), "email", "This field must be a valid email address")
	form.CheckField(validator.NotBlank(form.Password), "password", "This field cannot be blank")
	form.CheckField(validator.MinChars(form.Password, 8), "password", "This field must be 8 characters long")

	if !form.Valid() {
		data := app.newTemplateData(req)
		data.Form = form

		app.render(w, http.StatusUnprocessableEntity, "signup.gohtml", data)
		return
	}

	err = app.users.Insert(form.Name, form.Email, form.Password)
	if err != nil {
		if errors.Is(err, models.ErrDuplicateEmail) {
			form.AddFieldError("email", "Email address is already in use")

			data := app.newTemplateData(req)
			data.Form = form
			app.render(w, http.StatusUnprocessableEntity, "signup.gohtml", data)
		} else {
			app.serverError(w, err)
		}
		return
	}

	app.sessionManager.Put(req.Context(), "flash", "Your signup was successful. Please log in.")

	http.Redirect(w, req, "/user/login", http.StatusSeeOther)
}

func (app *application) userLogin(w http.ResponseWriter, req *http.Request) {
	data := app.newTemplateData(req)
	data.Form = userLoginForm{}
	app.render(w, http.StatusOK, "login.gohtml", data)
}

func (app *application) userLoginPost(w http.ResponseWriter, req *http.Request) {
	var form userLoginForm

	err := app.decodePostForm(req, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form.CheckField(validator.NotBlank(form.Email), "email", "This field cannot be blank")
	form.CheckField(validator.Matches(form.Email, validator.EmailRX), "email", "This field must be a valid email address")
	form.CheckField(validator.NotBlank(form.Password), "password", "This field cannot be blank")

	if !form.Valid() {
		data := app.newTemplateData(req)
		data.Form = form
		app.render(w, http.StatusUnprocessableEntity, "login.gohtml", data)
		return
	}

	id, err := app.users.Authenticate(form.Email, form.Password)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			form.AddNonFieldError("Email or password is incorrect")

			data := app.newTemplateData(req)
			data.Form = form
			app.render(w, http.StatusUnprocessableEntity, "login.gohtml", data)
		} else {
			app.serverError(w, err)
		}
		return
	}

	err = app.sessionManager.RenewToken(req.Context())
	if err != nil {
		app.serverError(w, err)
		return
	}

	app.sessionManager.Put(req.Context(), "authenticatedUserId", id)

	http.Redirect(w, req, "/snippet/create", http.StatusSeeOther)
}

func (app *application) userLogoutPost(w http.ResponseWriter, req *http.Request) {
	err := app.sessionManager.RenewToken(req.Context())
	if err != nil {
		app.serverError(w, err)
		return
	}

	app.sessionManager.Remove(req.Context(), "authenticatedUserId")
	app.sessionManager.Put(req.Context(), "flash", "You've been logged out successfully!")

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func (app *application) snippetView(w http.ResponseWriter, req *http.Request) {
	params := httprouter.ParamsFromContext(req.Context())

	id, err := strconv.Atoi(params.ByName("id"))
	if err != nil || id < 1 {
		app.notFound(w)
		return
	}

	snippet, err := app.snippets.Get(id)
	if err != nil {
		if errors.Is(err, models.ErrNoRecord) {
			app.notFound(w)
		} else {
			app.serverError(w, err)
		}
		return
	}

	data := app.newTemplateData(req)
	data.Snippet = snippet

	app.render(w, http.StatusOK, "view.gohtml", data)
}

func (app *application) snippetCreate(w http.ResponseWriter, req *http.Request) {
	data := app.newTemplateData(req)

	data.Form = snippetCreateForm{
		Expires: 365,
	}

	app.render(w, http.StatusOK, "create.gohtml", data)
}

func (app *application) snippetCreatePost(w http.ResponseWriter, req *http.Request) {
	var form snippetCreateForm

	err := app.decodePostForm(req, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	err = app.formDecoder.Decode(&form, req.PostForm)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form.CheckField(validator.NotBlank(form.Title), "title", "This field cannot be blank")
	form.CheckField(validator.MaxChars(form.Title, 100), "title", "This field cannot be more than 100 characters long")
	form.CheckField(validator.NotBlank(form.Content), "content", "This field cannot be blank")
	form.CheckField(validator.PermittedInt(form.Expires, 1, 7, 365), "expires", "Rthis filed must equal 1, 7, or 365")

	if !form.Valid() {
		data := app.newTemplateData(req)
		data.Form = form
		app.render(w, http.StatusUnprocessableEntity, "create.gohtml", data)
		return
	}

	id, err := app.snippets.Insert(form.Title, form.Content, form.Expires)
	if err != nil {
		app.serverError(w, err)
	}

	app.sessionManager.Put(req.Context(), "flash", "Snippet successfully created!")

	http.Redirect(w, req, fmt.Sprintf("/snippet/view/%d", id), http.StatusSeeOther)
}
