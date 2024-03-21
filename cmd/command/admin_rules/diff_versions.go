package admin_rules

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/common-fate/common-fate/pkg/types"
	"github.com/common-fate/glide-cli/pkg/client"
	"github.com/common-fate/glide-cli/pkg/config"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/urfave/cli/v2"

	"sigs.k8s.io/yaml"

	"github.com/gocarina/gocsv"
)

type accessRuleDetailSubset struct {
	// Approver config for access rules
	Name              string                       `json:"name"`
	Description       string                       `json:"description"`
	DescriptionSha256 string                       `json:"descriptionSha256"`
	Groups            []string                     `json:"groups"`
	Approval          types.ApproverConfig         `json:"approval"`
	Target            types.AccessRuleTargetDetail `json:"target"`
	TimeConstraints   types.TimeConstraints        `json:"timeConstraints"`
}

func convertToAccessRuleDetailSubset(rule types.AccessRuleDetail) accessRuleDetailSubset {
	descriptionSha256 := fmt.Sprintf("%x", sha256.Sum256([]byte(rule.Description)))

	// Some changes to make diff easier to read
	description := rule.Description
	description = strings.ReplaceAll(description, " @auto-approval:", "\n@auto-approval:")
	description = strings.ReplaceAll(description, " </defails>", "\n</defails>")

	return accessRuleDetailSubset{
		Name:              rule.Name,
		Description:       description,
		DescriptionSha256: descriptionSha256,
		Groups:            rule.Groups,
		Approval:          rule.Approval,
		Target:            rule.Target,
		TimeConstraints:   rule.TimeConstraints,
	}
}

type DiffEntry struct {
	RuleID    string    `json:"ruleId"`
	Version   string    `json:"version"`
	UpdatedBy string    `json:"updatedBy"`
	UpdatedAt time.Time `json:"updatedAt"`
	Diff      string    `json:"diff"`
}

var diffVersions = cli.Command{
	Name:  "diff-versions",
	Usage: "Get Access Rules Versions and prints the diff between them",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{Name: "rule-id", Usage: "Rule ids to list the versions from. Omit for all.", Aliases: []string{"r"}},
		&cli.StringFlag{Name: "format", Usage: "Output format: text, json, csv", Aliases: []string{"f"}},
		&cli.BoolFlag{Name: "exclude-bot-governance-api", Usage: "Exclude changes done via terraform API. Only in text mode.", Aliases: []string{"x"}},
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
		format := c.String("format")
		excludeBotGovernanceApi := c.Bool("exclude-bot-governance-api")

		if len(ruleIDs) == 0 {
			rules, err := cf.AdminListAccessRulesWithResponse(ctx, &types.AdminListAccessRulesParams{})
			if err != nil {
				return err
			}
			for _, rule := range rules.JSON200.AccessRules {
				ruleIDs = append(ruleIDs, rule.ID)
			}
		}

		diffs := []DiffEntry{}

		for _, ruleID := range ruleIDs {
			versions, err := cf.AdminGetAccessRuleVersionsWithResponse(ctx, ruleID)
			if err != nil {
				return err
			}
			accessRules := versions.JSON200.AccessRules
			if len(accessRules) == 0 {
				return fmt.Errorf("No versions found for rule %s", ruleID)
			}

			sort.Slice(accessRules, func(i, j int) bool {
				return accessRules[i].Metadata.UpdatedAt.Before(accessRules[j].Metadata.UpdatedAt)
			})

			prevRule := types.AccessRuleDetail{
				ID:      accessRules[0].ID,
				Version: "initial",
				Metadata: types.AccessRuleMetadata{
					UpdatedBy: "n/a",
				},
			}

			for _, rule := range accessRules {
				// Convert objects to YAML
				yaml1, err := yaml.Marshal(convertToAccessRuleDetailSubset(prevRule))
				if err != nil {
					return err
				}
				yaml2, err := yaml.Marshal(convertToAccessRuleDetailSubset(rule))
				if err != nil {
					return err
				}

				fromFile := fmt.Sprintf("Rule: %s By:%s Version:%s", prevRule.ID, prevRule.Metadata.UpdatedBy, prevRule.Version)
				toFile := fmt.Sprintf("Rule: %s By:%s Version:%s", rule.ID, rule.Metadata.UpdatedBy, rule.Version)

				// Calculate the difference between YAML representations
				diff := difflib.UnifiedDiff{
					A:        difflib.SplitLines(string(yaml1)),
					B:        difflib.SplitLines(string(yaml2)),
					FromFile: fromFile,
					FromDate: prevRule.Metadata.UpdatedAt.String(),
					ToFile:   toFile,
					ToDate:   rule.Metadata.UpdatedAt.String(),
					Context:  3,
				}
				textDiff, err := difflib.GetUnifiedDiffString(diff)
				if err != nil {
					return err
				}

				diffs = append(diffs, DiffEntry{
					RuleID:    rule.ID,
					Version:   rule.Version,
					UpdatedBy: rule.Metadata.UpdatedBy,
					UpdatedAt: rule.Metadata.UpdatedAt,
					Diff:      textDiff,
				})

				prevRule = rule
			}
		}

		switch format {
		case "text":
			for _, diff := range diffs {
				fmt.Printf("Change by %s on %s\n", diff.UpdatedBy, diff.UpdatedAt.String())
				if excludeBotGovernanceApi && diff.UpdatedBy == "bot_governance_api" {
					fmt.Println("Change done by bot_governance_api. Skipping diff")
					continue
				}
				// Print the difference
				fmt.Println(diff.Diff)
			}

		case "json":
			err := json.NewEncoder(os.Stdout).Encode(diffs)
			if err != nil {
				return err
			}

		case "csv":
			csvContent, err := gocsv.MarshalString(&diffs)
			if err != nil {
				return err
			}
			fmt.Println(csvContent) // Display all clients as CSV string
		}

		return nil
	},
}
