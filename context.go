package goatcontext

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type Context struct {
	context.Context

	authorize Authorize
	authToken string
	origin    string
}

type Authorize struct {
	UserId   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
}

func New(request *http.Request) (Context, error) {
	auth, err := parseToken(getToken(request))
	if err != nil {
		return Context{}, err
	}

	return Context{
		Context:   request.Context(),
		authorize: auth,
		authToken: getToken(request),
		origin:    getOrigin(request),
	}, nil
}

func (c *Context) Authorize() Authorize {
	return c.authorize
}

func (c *Context) AuthToken() string {
	return c.authToken
}

func (c *Context) Origin() string {
	return c.origin
}

func (c *Context) SetOrigin(origin string) {
	c.origin = origin
}

func (c *Context) IsAuthorized() bool {
	return c.authorize.UserId != "" && c.authorize.Username != "" && len(c.authToken) == 0
}

func getToken(r *http.Request) string {
	return r.Header.Get("Authorization")
}

func getOrigin(r *http.Request) string {
	return r.Header.Get("Origin")
}

func parseToken(token string) (Authorize, error) {
	if len(token) == 0 {
		return Authorize{}, nil
	}

	tokenSplit := strings.Split(token, ".")
	if len(tokenSplit) < 2 {
		return Authorize{}, errors.New("invalid token")
	}

	var auth Authorize
	if err := json.Unmarshal([]byte(tokenSplit[1]), &auth); err != nil {
		return Authorize{}, errors.New("invalid token")
	}

	return auth, nil
}
