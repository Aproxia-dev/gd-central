package oauth

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/markbates/goth/gothic"
)

var JwtSecret = []byte(os.Getenv("JWT_SECRET"))

func OAuthClientRedirect(c *fiber.Ctx) error {
	handler := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		q.Set("provider", c.Params("provider"))
		req.URL.RawQuery = q.Encode()

		user, err := gothic.CompleteUserAuth(res, req)
		log.Print(err)
		if err != nil {
			gothic.BeginAuthHandler(res, req)
			return
		} else {
			userJson, _ := json.Marshal(user)
			res.Header().Set("Content-Type", "application/json")
			res.WriteHeader(http.StatusOK)
			res.Write(userJson)
		}
	})

	return adaptor.HTTPHandler(handler)(c)
}

func OAuthClientCallback(c *fiber.Ctx) error {
	handler := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		user, err := gothic.CompleteUserAuth(res, req)
		if err != nil {
			http.Error(res, err.Error(), http.StatusUnauthorized)
			return
		}

		userJson, _ := json.Marshal(user)
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)
		res.Write(userJson)
	})

	return adaptor.HTTPHandler(handler)(c)

	// var user db.User
	// result := db.DB.
	// 	Where(db.User{DiscordID: OauthUser.UserID}).
	// 	Assign(db.User{
	// 		Name:       OauthUser.RawData["global_name"].(string),
	// 		DiscordTag: OauthUser.Name,
	// 	}).
	// 	FirstOrCreate(&user)
	// if result.Error != nil {
	// 	log.Fatalf("DB Error: %v", result.Error)
	// 	http.Error(w, "Internal Server Error!", http.StatusInternalServerError)
	// 	return
	// } else {
	// 	db.DB.Model(&user).
	// 		Update("name", OauthUser.RawData["global_name"].(string)).
	// 		Update("DiscordTag", OauthUser.Name)
	// }

	// token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
	// 	"name":    user.Name,
	// 	"user_id": user.ID,
	// 	"exp":     time.Now().Add(24 * 30 * time.Hour).Unix(),
	// })
	// tokenString, err := token.SignedString(JwtSecret)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	// response := fmt.Sprintf(`{"User": {"ID": "%s", "Name": "%s", "Tag": "%s"}}`,
	// 	user.DiscordID, user.DiscordTag, user.Name)

	// http.SetCookie(w, &http.Cookie{
	// 	Name:     "jwt",
	// 	Value:    tokenString,
	// 	HttpOnly: true,
	// 	SameSite: http.SameSiteLaxMode,
	// 	Path:     "/",
	// 	Expires:  time.Now().Add(24 * 30 * time.Hour),
	// })

	// w.Header().Set("Content-Type", "application/json")
	// w.WriteHeader(http.StatusOK)
	// w.Write([]byte(response))
}
