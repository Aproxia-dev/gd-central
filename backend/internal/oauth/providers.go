package oauth

import (
	"os"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/discord"
)

func GetProviders() {
	goth.UseProviders(
		discord.New(
			os.Getenv("DISCORD_KEY"),
			os.Getenv("DISCORD_SECRET"),
			"http://localhost:8000/auth/discord/callback",
			discord.ScopeIdentify,
		),
	)
}
