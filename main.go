package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/lmittmann/tint"
)

const userAgent = "Dell SonicWALL NetExtender for Linux 8.1.789"

// Config holds all runtime configuration for the VPN session.
type Config struct {
	Server      string
	Port        int
	Username    string
	Password    string
	Domain      string
	Fingerprint string
	MaxLine     int
	DNSBackend  string // "auto", "systemd-resolved", "resolvconf", "networkmanager", "none"
}

// cachedConfig is the subset of Config persisted between runs.
// Password is intentionally excluded.
type cachedConfig struct {
	Server      string `json:"server"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Domain      string `json:"domain"`
	Fingerprint string `json:"fingerprint,omitempty"`
	DNSBackend  string `json:"dns_backend"`
}

func cacheFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "nxbender", "config.json")
}

func loadCache() cachedConfig {
	c := cachedConfig{Port: 443, DNSBackend: "auto"}
	data, err := os.ReadFile(cacheFilePath())
	if err != nil {
		return c
	}
	json.Unmarshal(data, &c)
	if c.Port == 0 {
		c.Port = 443
	}
	if c.DNSBackend == "" {
		c.DNSBackend = "auto"
	}
	return c
}

func saveCache(c cachedConfig) {
	path := cacheFilePath()
	os.MkdirAll(filepath.Dir(path), 0700)
	data, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(path, data, 0600)
}

func main() {
	c := loadCache()

	// Collect connection details interactively.
	answers := struct {
		Server      string
		Port        string
		Username    string
		Domain      string
		Fingerprint string
		DNSBackend  string
	}{}

	err := survey.Ask([]*survey.Question{
		{Name: "Server", Prompt: &survey.Input{Message: "Server", Default: c.Server}, Validate: survey.Required},
		{Name: "Port", Prompt: &survey.Input{Message: "Port", Default: strconv.Itoa(c.Port)}},
		{Name: "Username", Prompt: &survey.Input{Message: "Username", Default: c.Username}, Validate: survey.Required},
		{Name: "Domain", Prompt: &survey.Input{Message: "Domain", Default: c.Domain}, Validate: survey.Required},
		{Name: "Fingerprint", Prompt: &survey.Input{Message: "TLS fingerprint (optional)"}},
		{Name: "DNSBackend", Prompt: &survey.Select{
			Message: "DNS backend",
			Options: []string{"auto", "systemd-resolved", "resolvconf", "networkmanager", "none"},
			Default: c.DNSBackend,
		}},
	}, &answers)
	if err != nil {
		os.Exit(1) // user cancelled (Ctrl-C)
	}

	// Fingerprint prompt doesn't show previous value to avoid leaking it;
	// keep the cached value if the user left it blank.
	fingerprint := answers.Fingerprint
	if fingerprint == "" {
		fingerprint = c.Fingerprint
	}

	var password string
	if err := survey.AskOne(&survey.Password{Message: "Password"}, &password, survey.WithValidator(survey.Required)); err != nil {
		os.Exit(1)
	}

	port, _ := strconv.Atoi(answers.Port)
	if port == 0 {
		port = 443
	}

	cfg := &Config{
		Server:      answers.Server,
		Port:        port,
		Username:    answers.Username,
		Domain:      answers.Domain,
		Fingerprint: fingerprint,
		DNSBackend:  answers.DNSBackend,
		Password:    password,
		MaxLine:     1500,
	}

	saveCache(cachedConfig{
		Server:      cfg.Server,
		Port:        cfg.Port,
		Username:    cfg.Username,
		Domain:      cfg.Domain,
		Fingerprint: cfg.Fingerprint,
		DNSBackend:  cfg.DNSBackend,
	})

	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stderr, &tint.Options{
			Level:      slog.LevelInfo,
			TimeFormat: time.TimeOnly,
		}),
	))

	if err := NewNXSession(cfg).Run(); err != nil {
		slog.Error("fatal", tint.Err(err))
		os.Exit(1)
	}
}
