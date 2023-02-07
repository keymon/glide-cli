package config

import (
	"fmt"

	"github.com/common-fate/clio/clierr"
)

type Config struct {
	CurrentContext string `toml:"current_context" json:"current_context"`
	// Contexts allows multiple Common Fate tenancies to be switched between easily.
	// We don't have official support for this yet in the CLI,
	// but the config structure supports it so that it can be easily added in future.
	Contexts map[string]Context `toml:"context" json:"context"`
}

type Context struct {
	DashboardURL string `toml:"dashboard_url" json:"dashboard_url"`
}

// Current loads the current context as specified in the 'current_context' field in the config file.
// It returns an error if there are no contexts, or if the 'current_context' field doesn't match
// any contexts defined in the config file.
func (c Config) Current() (*Context, error) {
	if c.Contexts == nil {
		return nil, clierr.New("No contexts were found in Common Fate config file.", clierr.Infof("To log in to Common Fate, run: 'cf login'"))
	}

	got, ok := c.Contexts[c.CurrentContext]
	if !ok {
		return nil, clierr.New(fmt.Sprintf("Could not find context '%s' in Common Fate config file", c.CurrentContext), clierr.Infof("To log in to Common Fate, run: 'cf login'"))
	}

	return &got, nil
}

// CurrentOrEmpty returns the current context,
// or an empty context if it can't be found.
func (c Config) CurrentOrEmpty() Context {
	if c.Contexts == nil {
		return Context{}
	}
	got, ok := c.Contexts[c.CurrentContext]
	if !ok {
		return Context{}
	}
	return got
}

// Default returns an empty config.
func Default() *Config {
	return &Config{
		CurrentContext: "",
		Contexts:       map[string]Context{},
	}
}

// DashboardURLs returns all of the dashboard URLs available
// across different contexts.
func (c Config) DashboardURLs() []string {
	var urls []string
	for _, c := range c.Contexts {
		urls = append(urls, c.DashboardURL)
	}
	return urls
}