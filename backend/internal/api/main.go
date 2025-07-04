package api

import (
	"github.com/Aproxia-dev/gd-central/backend/internal/oauth"
	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
)

func ping(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "pong"})
}

func RegisterRoutes(app *fiber.App) error {
	app.Get("/ping", ping)
	app.Get("/auth/discord", adaptor.HTTPHandlerFunc(oauth.DiscordAuthRedirect))
	app.Get("/auth/discord/callback", adaptor.HTTPHandlerFunc(oauth.DiscordAuthCallback))
	return nil
}
