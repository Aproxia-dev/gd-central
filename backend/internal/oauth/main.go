package oauth

import (
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/markbates/goth/gothic"
)

func DiscordAuthRedirect(c *fiber.Ctx) error {
	c.Request().Header.Set("Provider", "discord")
	r := c.Context().Request()
	w := fiberToResponseWriter{c}
	gothic.BeginAuthHandler(w, r)
	return nil
}

func DiscordAuthCallback(c *fiber.Ctx) error {
	c.Request().Header.Set("Provider", "discord")
	r := c.Context().Request()
	w := fiberToResponseWriter{c}
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString(fmt.Sprintf("Auth failed: %v", err))
	}
	c.JSON(user)
}

// Adapter to make Fiber compatible with http.ResponseWriter
type fiberToResponseWriter struct {
	*fiber.Ctx
}

func (f fiberToResponseWriter) Header() http.Header {
	h := http.Header{}
	f.Response().Header.VisitAll(func(k, v []byte) {
		h.Add(string(k), string(v))
	})
	return h
}
func (f fiberToResponseWriter) Write(b []byte) (int, error) {
	return f.Ctx.Write(b)
}
func (f fiberToResponseWriter) WriteHeader(statusCode int) {
	f.Ctx.Status(statusCode)
}
