package oauth

import (
	"os"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/discord"
	"github.com/markbates/goth/providers/github"
)

func GetProviders() {
	discordCb := "http://localhost:8080/auth/user/discord/callback"
	githubCb := "http://localhost:8080/auth/dev/github/callback"
	if os.Getenv("APP_ENV") == "prod" {
		discordCb = "something else lmao"
		githubCb = "something else lmao"
	}
	goth.UseProviders(
		discord.New(
			os.Getenv("DISCORD_KEY"),
			os.Getenv("DISCORD_SECRET"),
			discordCb,
			discord.ScopeIdentify,
		),
		github.New(
			os.Getenv("GITHUB_KEY"),
			os.Getenv("GITHUB_SECRET"),
			githubCb,
		),
	)
}

var ProviderTypes = map[string][]string{
	"user": {
		"discord",
	},
	"dev": {
		"github",
	},
}
