package goatcontext

import (
	"context"
	"encoding/base64"
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
	UserId   int    `json:"user_id"`
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
	return c.authorize.UserId != 0 && c.authorize.Username != "" && len(c.authToken) == 0
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

	userInfo := tokenSplit[1]
	if len(userInfo)%4 != 0 {
		for i := 0; i < len(userInfo)%4; i++ {
			userInfo += "="
		}
	}

	b, err := base64.StdEncoding.DecodeString(userInfo)
	if err != nil {
		return Authorize{}, err
	}

	var auth Authorize
	if err = json.Unmarshal(b, &auth); err != nil {
		return Authorize{}, errors.New("invalid token")
	}

	return auth, nil
}
