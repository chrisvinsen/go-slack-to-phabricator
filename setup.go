package slack

import (
	"context"
	"os"
)

type Environment struct {
	phabAPIToken			string
	slackSecret				string
	slackToken				string
	botToken				string
}

func setup(ctx context.Context) Environment {
	var env Environment

	env.phabAPIToken = os.Getenv("PHAB_API_TOKEN")
	env.slackSecret = os.Getenv("SLACK_SECRET")
	env.slackToken = os.Getenv("SLACK_TOKEN")
	env.botToken = os.Getenv("BOT_TOKEN")

	return env
}