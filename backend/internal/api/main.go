package api

import (
	"github.com/gofiber/fiber/v2"
)

func ping(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "pong"})
}

func RegisterRoutes(app *fiber.App) error {
	app.Get("/ping", ping)
}
