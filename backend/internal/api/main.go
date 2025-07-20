package api

import (
	"os"

	"github.com/Aproxia-dev/gd-central/backend/internal/oauth"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

var JwtSecret = []byte(os.Getenv("JWT_SECRET"))
var JwtWare = jwtware.New(
	jwtware.Config{
		TokenLookup:  "cookie:jwt",
		SigningKey:   jwtware.SigningKey{Key: JwtSecret},
		ErrorHandler: jwtError,
	},
)

func jwtError(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": "Unauthorized",
	})
}

func ping(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "pong"})
}

func whoami(c *fiber.Ctx) error {
	t := c.Locals("user").(*jwt.Token)
	claims := t.Claims.(jwt.MapClaims)
	return c.JSON(fiber.Map{
		"name":   claims["name"],
		"userID": claims["user_id"],
	})
}

func RegisterRoutes(app *fiber.App) error {
	app.Get("/ping", ping)
	app.Get("/auth/:provider", oauth.OAuthClientRedirect)
	app.Get("/auth/:provider/callback", oauth.OAuthClientCallback)
	app.Get("/whoami/:usertype", JwtWare, whoami)
	return nil
}
