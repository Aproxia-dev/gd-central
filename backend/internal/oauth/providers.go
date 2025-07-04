package oauth

import (
	"os"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/discord"
)

func GetProviders() {
	dcb := "http://localhost:8080/auth/discord/callback"
	if os.Getenv("APP_ENV") == "prod" {
		dcb = "something else lmao"
	}
	goth.UseProviders(
		discord.New(
			os.Getenv("DISCORD_KEY"),
			os.Getenv("DISCORD_SECRET"),
			dcb,
			discord.ScopeIdentify,
		),
	)
}
