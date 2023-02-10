package command

import (
	"errors"
	"net/http"

	"github.com/99designs/keyring"
	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/cli/pkg/authflow"
	"github.com/common-fate/cli/pkg/config"
	"github.com/common-fate/cli/pkg/tokenstore"
	"github.com/common-fate/clio"
	"github.com/pkg/browser"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
)

var Login = cli.Command{
	Name:   "login",
	Usage:  "Log in to Common Fate",
	Action: defaultLoginFlow.LoginAction,
}

// defaultLoginFlow is the login flow without any
// customisations to token storage.
var defaultLoginFlow LoginFlow

type LoginFlow struct {
	// Keyring optionally overrides the keyring that auth tokens are saved to.
	Keyring keyring.Keyring
	// ForceInteractive forces the survey prompt to appear
	ForceInteractive bool
}

func (lf LoginFlow) LoginAction(c *cli.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	var url string
	if !lf.ForceInteractive {
		// try and read the URL from the first provided argument
		url = c.Args().First()
	}

	var manualPrompt bool
	if url == "" {
		manualPrompt = true
		prompt := &survey.Input{
			Message: "Your Common Fate dashboard URL",
			Default: cfg.CurrentOrEmpty().DashboardURL,
		}
		survey.AskOne(prompt, &url, survey.WithValidator(survey.Required))
	}

	if url == "" {
		// if the user presses Control+C during the survery prompt, the url will still be empty
		return errors.New("url was empty")
	}

	if manualPrompt {
		// display a hint to the user
		clio.Infof("log in faster next time by running: '%s %s %s'", c.App.Name, c.Command.FullName(), url)
	}

	ctx := c.Context

	authResponse := make(chan authflow.Response)

	var g errgroup.Group

	authServer, err := authflow.FromDashboardURL(ctx, authflow.Opts{
		Response:     authResponse,
		DashboardURL: url,
	})
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:    ":18900",
		Handler: authServer.Handler(),
	}

	ts := tokenstore.New(cfg.CurrentContext, tokenstore.WithKeyring(lf.Keyring))

	// run the auth server on localhost
	g.Go(func() error {
		clio.Debugw("starting HTTP server", "address", server.Addr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			return err
		}
		clio.Debugw("auth server closed")
		return nil
	})

	// read the returned ID token from Cognito
	g.Go(func() error {
		res := <-authResponse

		err := server.Shutdown(ctx)
		if err != nil {
			return err
		}

		// check that the auth flow didn't error out
		if res.Err != nil {
			return err
		}

		// update the config file
		cfg.CurrentContext = "default"
		cfg.Contexts["default"] = config.Context{
			DashboardURL: res.DashboardURL,
		}
		err = config.Save(cfg)
		if err != nil {
			return err
		}

		err = ts.Save(res.Token)
		if err != nil {
			return err
		}

		clio.Successf("logged in")

		return nil
	})

	// open the browser and read the token
	g.Go(func() error {
		u := "http://localhost:18900/auth/cognito/login"
		clio.Infof("Opening your web browser to: %s", u)
		err := browser.OpenURL(u)
		if err != nil {
			clio.Errorf("error opening browser: %s", err)
		}
		return nil
	})

	err = g.Wait()
	if err != nil {
		return err
	}

	return nil
}
