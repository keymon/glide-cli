package admin_rules

import (
	"encoding/json"
	"os"

	"github.com/common-fate/common-fate/pkg/types"
	"github.com/common-fate/glide-cli/pkg/client"
	"github.com/common-fate/glide-cli/pkg/config"
	"github.com/urfave/cli/v2"
)

type foundReport struct {
	ID            string
	Name          string
	TargetGroupID string
	Versions      []string
}

var findTarget = cli.Command{
	Name:  "find-target",
	Usage: "Search across all Access Rules Versions for a specific target",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{Name: "rule-id", Usage: "Rule ids to list the versions from. Omit for all.", Aliases: []string{"r"}},
		&cli.StringSliceFlag{Name: "target-id", Usage: "Target ids to search. ", Aliases: []string{"t"}},
	},
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

		targetIds := c.StringSlice("target-id")

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

		foundVersionRules := map[string][]types.AccessRuleDetail{}
		for _, target := range targetIds {
			for _, rule := range accessRules {
				for _, group := range rule.Target.With.AdditionalProperties["groupId"].Values {
					if target == group {
						if _, ok := foundVersionRules[rule.ID]; !ok {
							foundVersionRules[rule.ID] = []types.AccessRuleDetail{}
						}
						foundVersionRules[rule.ID] = append(foundVersionRules[rule.ID], rule)
					}
				}
			}
		}

		report := []foundReport{}
		for ruleID, rules := range foundVersionRules {
			versionIDs := []string{}
			for _, ruleVersion := range rules {
				versionIDs = append(versionIDs, ruleVersion.Version)
			}

			report = append(report, foundReport{
				ID:       ruleID,
				Name:     rules[len(rules)-1].Name,
				Versions: versionIDs,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(report)
		if err != nil {
			return err
		}

		return nil
	},
}
