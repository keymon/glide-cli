package admin_rules

import (
	"encoding/json"
	"os"

	"github.com/common-fate/common-fate/pkg/types"
	"github.com/common-fate/glide-cli/pkg/client"
	"github.com/common-fate/glide-cli/pkg/config"
	"github.com/urfave/cli/v2"
)

var list = cli.Command{
	Name:  "list",
	Usage: "List Access Rules",
	Action: func(c *cli.Context) error {
		ctx := c.Context

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		cf, err := client.FromConfig(ctx, cfg)
		if err != nil {
			return err
		}
		rules, err := cf.AdminListAccessRulesWithResponse(ctx, &types.AdminListAccessRulesParams{})

		if err != nil {
			return err
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		enc.Encode(rules.JSON200.AccessRules)

		return nil
	},
}
