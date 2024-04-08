package admin_rules

import (
	"encoding/json"
	"os"

	"github.com/common-fate/common-fate/pkg/types"
	"github.com/common-fate/glide-cli/pkg/client"
	"github.com/common-fate/glide-cli/pkg/config"
	"github.com/urfave/cli/v2"
)

var listVersions = cli.Command{
	Name:  "list-versions",
	Usage: "List Access Rules Versions",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{Name: "rule-id", Usage: "Rule ids to list the versions from. Omit for all.", Aliases: []string{"r"}},
	},
	Action: func(c *cli.Context) error {
		ctx := c.Context

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		cf, err := client.FromConfig(ctx, cfg)
		if err != nil {
			return err
		}
		ruleIDs := c.StringSlice("rule-id")
		if len(ruleIDs) == 0 {
			rules, err := cf.AdminListAccessRulesWithResponse(ctx, &types.AdminListAccessRulesParams{})
			if err != nil {
				return err
			}
			for _, rule := range rules.JSON200.AccessRules {
				ruleIDs = append(ruleIDs, rule.ID)
			}
		}

		accessRules := []types.AccessRuleDetail{}

		for _, ruleID := range ruleIDs {
			versions, err := cf.AdminGetAccessRuleVersionsWithResponse(ctx, ruleID)
			if err != nil {
				return err
			}
			accessRules = append(accessRules, versions.JSON200.AccessRules...)
		}
		enc.Encode(accessRules)
		return nil
	},
}
