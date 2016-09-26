package main

import (
	"os"

	"github.com/joho/godotenv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/slack"

	cascadestore "github.com/k2wanko/go-appengine-sessioncascade"
)

var oauthConf *oauth2.Config

func init() {
	if isDevServer() {
		err := godotenv.Load("dev.env")
		if err != nil {
			panic(err)
		}
	}

	store = cascadestore.NewCascadeStore(cascadestore.DistributedBackends, []byte(`session secret string.`))

	clientID := os.Getenv("SLACK_CLIENT_ID")
	clientSecret := os.Getenv("SLACK_CLIENT_SECRET")
	if clientID == "" {
		panic("clientID is empty")
	}
	if clientSecret == "" {
		panic("clientSecret is empty")
	}
	oauthConf = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes: []string{
			"users:read",
		},
		Endpoint: slack.Endpoint,
	}
}
