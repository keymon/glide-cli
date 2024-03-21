package admin_rules

import "github.com/urfave/cli/v2"

var Command = cli.Command{
	Name:  "admin_rules",
	Usage: "View Access Rules as Admin",
	Subcommands: []*cli.Command{
		&list,
		&listVersions,
		&diffVersions,
		&findTarget,
	},
}
