package oauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/markbates/goth/gothic"
)

func DiscordAuthRedirect(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("provider", "discord")
	r.URL.RawQuery = q.Encode()
	gothic.BeginAuthHandler(w, r)
}

func DiscordAuthCallback(w http.ResponseWriter, r *http.Request) {
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Auth failed: %v", err), http.StatusUnauthorized)
		return
	}
	userJson, _ := json.MarshalIndent(user, "", "  ")
	log.Println(string(userJson))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
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
