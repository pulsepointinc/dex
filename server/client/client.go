package client

import (
	"net/http"
	"github.com/gorilla/mux"
	"path/filepath"
	"fmt"
	"html/template"
	"github.com/sirupsen/logrus"
	"net/url"
	"strings"
	"github.com/coreos/dex/server"
	"golang.org/x/oauth2"
	"time"
	"github.com/coreos/go-oidc"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
)

type InternalClient struct {
	// Used to form back redirect URL
	ClientURL        string `json:"clientURL"`

	// Used to access dex by https
	RootCA           string `json:"rootCA"`

	ClientID         string `json:"clientID"`
	ClientSecret     string `json:"clientSecret"`
	// Used to access dex from client internally to get refresh and id tokens
	InternalIssueURL string `json:"internalIssuerURL"`

	// User name used in kubectl
	LocalUserName    string `json:"localUserName"`

	// CA Path used as kubectl idp-certificate-authority
	LocalRootCA      string `json:"localRootCA"`
}

type Config struct {
	Issuer     string
	IssuerURL  *url.URL
	Config     InternalClient
	WebConfig  server.WebConfig
	Logger     logrus.FieldLogger
	HttpRouter *mux.Router
}

type Client struct {
	config       *Config
	templates    Templates
	redirectURL  string
	logger       logrus.FieldLogger
	client       *http.Client
	oauth2Config oauth2.Config
}

type Templates struct {
	clientIndex  *template.Template
	clientResult *template.Template
}

const myAppState = "PulsePoint_internal_client"

var scopes = []string{"openid", "profile", "email", "groups", "offline_access"}

func NewClient(config *Config) (*Client, error) {
	tmpls, err := parseTemplates(config)
	if err != nil {
		return nil, fmt.Errorf("parse template files: %v", err)
	}
	httpClient, err := createHttpClient(config)
	if err != nil {
		return nil, fmt.Errorf("Create http transport: %v", err)
	}
	redirectURL := config.Config.ClientURL + "callback"

	c := &Client{
		config:      config,
		redirectURL: redirectURL,
		logger:      config.Logger,
		client:      httpClient,
		templates: Templates{
			clientIndex:  tmpls.Lookup("clientIndex.html"),
			clientResult: tmpls.Lookup("clientResult.html"),
		},
		oauth2Config: oauth2.Config{
			ClientID:     config.Config.ClientID,
			ClientSecret: config.Config.ClientSecret,
			Scopes:       scopes,
			RedirectURL:  redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.Config.InternalIssueURL + "/auth",
				TokenURL: config.Config.InternalIssueURL + "/token",
			},
		},
	}

	router := config.HttpRouter
	router.HandleFunc("/", c.handleIndex)
	router.HandleFunc("/callback", c.handleCallback)
	router.HandleFunc("/rootCA", func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFile(writer, request, c.config.Config.RootCA)
	})

	return c, nil
}

func parseTemplates(config *Config) (*template.Template, error) {
	dir := config.WebConfig.Dir
	if dir == "" {
		dir = "./web"
	}
	templatesDir := filepath.Join(dir, "templates")

	funcs := map[string]interface{}{
		"issuer": func() string { return config.WebConfig.Issuer },
		"logo":   func() string { return config.WebConfig.LogoURL },
		"url":    func(s string) string { return join(config.Issuer, s) },
		"lower":  strings.ToLower,
	}

	tmpls, err := template.New("").Funcs(funcs).ParseFiles(filepath.Join(templatesDir, "clientIndex.html"),
		filepath.Join(templatesDir, "clientResult.html"),
		filepath.Join(templatesDir, "header.html"),
		filepath.Join(templatesDir, "footer.html"),
	)
	return tmpls, err
}

func createHttpClient(config *Config) (*http.Client, error) {
	if config.Config.RootCA != "" {
		client, err := httpClientForRootCAs(config.Config.RootCA)
		if err != nil {
			return nil, err
		}
		return client, nil
	}

	return http.DefaultClient, nil
}

// return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(rootCAs string) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	rootCABytes, err := ioutil.ReadFile(rootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to read root-ca: %v", err)
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

func join(base, path string) string {
	b := strings.HasSuffix(base, "/")
	p := strings.HasPrefix(path, "/")
	switch {
	case b && p:
		return base + path[1:]
	case b || p:
		return base + path
	default:
		return base + "/" + path
	}
}

/*
http://127.0.0.1:5556/dex/auth?
client_id=example-app&
redirect_uri=http%3A%2F%2F127.0.0.1%3A5555%2Fcallback&
response_type=code&
scope=groups+openid+profile+email+offline_access&
state=I+wish+to+wash+my+irish+wristwatch
 */
func (c *Client) handleIndex(w http.ResponseWriter, r *http.Request) {
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {c.config.Config.ClientID},
		"redirect_uri":  {c.redirectURL},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {myAppState},
	}

	c.templates.clientIndex.Execute(w, struct {
		ServerUrl string
	}{c.config.Issuer + "/auth?" + v.Encode()})
}

func (c *Client) handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		token *oauth2.Token
	)

	ctx := oidc.ClientContext(r.Context(), c.client)
	switch r.Method {
	case "GET":
		// Authorization redirect callback from OAuth2 auth flow.
		if errMsg := r.FormValue("error"); errMsg != "" {
			http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		if state := r.FormValue("state"); state != myAppState {
			http.Error(w, fmt.Sprintf("expected state %q got %q", myAppState, state), http.StatusBadRequest)
			return
		}
		token, err = c.oauth2Config.Exchange(ctx, code)
	default:
		http.Error(w, fmt.Sprintf("method not implemented: %s", r.Method), http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	/*
	idToken, err := c.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to verify ID token: %v", err), http.StatusInternalServerError)
		return
	}
	var claims json.RawMessage
	idToken.Claims(&claims)

	buff := new(bytes.Buffer)
	json.Indent(buff, []byte(claims), "", "  ")
	*/

	c.templates.clientResult.Execute(w, struct {
		IdToken      string
		RefreshToken string
		IssuerUrl    string
		ClientId     string
		ClientSecret string
		UserName	 string
		CaPath       string
	}{
		IdToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		IssuerUrl:    c.config.Issuer,
		ClientId:     c.config.Config.ClientID,
		ClientSecret: c.config.Config.ClientSecret,
		UserName:     c.config.Config.LocalUserName,
		CaPath:       c.config.Config.LocalRootCA,
	})
}
