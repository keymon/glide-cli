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
	TargetGroupID string
	RuleID        string
	Name          string
	Versions      []string
	VersionCount  int
}

// findTarget is a cli command that searches for a specific target across all Access Rules Versions
// using the api of glide
var findTarget = cli.Command{
	Name:  "find-target",
	Usage: "Search across all Access Rules Versions for a specific target",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{Name: "rule-id", Usage: "Rule ids to list the versions from. Omit for all.", Aliases: []string{"r"}},
		&cli.StringSliceFlag{Name: "target-id", Usage: "Target ids to search. ", Aliases: []string{"t"}},
	},
	Action: func(c *cli.Context) error {

		// Client initialization
		ctx := c.Context

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		cf, err := client.FromConfig(ctx, cfg)
		if err != nil {
			return err
		}

		// Get the config parameters from command line
		targetIds := c.StringSlice("target-id")
		ruleIDs := c.StringSlice("rule-id")

		// If no rule id is provided, get all the rules from API
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

		// Retrieve all the versions of the rules and store them in accessRules
		// for processing next
		for _, ruleID := range ruleIDs {
			versions, err := cf.AdminGetAccessRuleVersionsWithResponse(ctx, ruleID)
			if err != nil {
				return err
			}
			accessRules = append(accessRules, versions.JSON200.AccessRules...)
		}

		foundVersionRulesPerGroup := map[string]map[string][]types.AccessRuleDetail{}
		// For each group ID in the targetIds, search for the group in the rule versions
		// and store the found versions in the foundVersionRulesPerGroup map
		for _, target := range targetIds {
			for _, rule := range accessRules {
				for _, group := range rule.Target.With.AdditionalProperties["groupId"].Values {
					if target == group {
						// Initialise structs/maps if not already present
						if _, ok := foundVersionRulesPerGroup[group]; !ok {
							foundVersionRulesPerGroup[group] = map[string][]types.AccessRuleDetail{}
						}
						if _, ok := foundVersionRulesPerGroup[group][rule.ID]; !ok {
							foundVersionRulesPerGroup[group][rule.ID] = []types.AccessRuleDetail{}
						}
						// Append the found rule version to the map
						foundVersionRulesPerGroup[group][rule.ID] = append(foundVersionRulesPerGroup[group][rule.ID], rule)
					}
				}
			}
		}

		report := []foundReport{}
		// Generate the report from the foundVersionRulesPerGroup map
		// for each target group
		for targetGroupID, foundVersionRules := range foundVersionRulesPerGroup {
			// For each found version
			for ruleID, rules := range foundVersionRules {
				versionIDs := []string{}
				// List all the version ids
				for _, ruleVersion := range rules {
					versionIDs = append(versionIDs, ruleVersion.Version)
				}

				// Add add the found report to the report slice
				report = append(report, foundReport{
					TargetGroupID: targetGroupID,
					RuleID:        ruleID,
					Name:          rules[len(rules)-1].Name,
					Versions:      versionIDs,
					VersionCount:  len(versionIDs),
				})
			}
		}

		// Encode the report in json
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(report)
		if err != nil {
			return err
		}

		return nil
	},
}
