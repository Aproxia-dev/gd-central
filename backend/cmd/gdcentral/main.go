package main

import (
	"github.com/Aproxia-dev/gd-central/backend/internal/api"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()
	api.RegisterRoutes(app)
	app.Listen(":8000")
}
