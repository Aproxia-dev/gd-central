package oauth

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/Aproxia-dev/gd-central/backend/internal/db"
	"github.com/gofiber/fiber/v2"
	"github.com/markbates/goth/gothic"
	"gorm.io/gorm"
)

func DiscordAuthRedirect(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("provider", "discord")
	r.URL.RawQuery = q.Encode()
	gothic.BeginAuthHandler(w, r)
}

func DiscordAuthCallback(w http.ResponseWriter, r *http.Request) {
	OauthUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Auth failed: %v", err), http.StatusUnauthorized)
		return
	}

	var user db.User
	result := db.DB.Where("discord_id = ?", OauthUser.UserID).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		user := db.User{
			DiscordID:   OauthUser.UserID,
			Name:        OauthUser.RawData["global_name"].(string),
			DiscordName: OauthUser.Name,
		}
		db.DB.Create(&user)
	} else if result.Error != nil {
		log.Fatalf("DB Error: %v", result.Error)
		http.Error(w, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	response := fmt.Sprintf(`{"User": {"ID": "%s", "Name": "%s", "Tag": "%s"}}`,
		user.DiscordID, user.DiscordName, user.Name)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
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
