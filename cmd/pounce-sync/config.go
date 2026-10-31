package main

import (
	"errors"
	"fmt"

	"github.com/BurntSushi/toml"
)

type config struct {
	Origin       string `toml:"origin"`
	DB           string `toml:"db"`
	Listen       string `toml:"listen"`
	Registration string `toml:"registration"`
	TLSCert      string `toml:"tls_cert"`
	TLSKey       string `toml:"tls_key"`
	RealIPHeader string `toml:"real_ip_header"`
	MaxRecords   int    `toml:"max_records"`
	RateIP       int    `toml:"rate_ip"`
	RateDevice   int    `toml:"rate_device"`
}

func loadConfig(path string) (*config, error) {
	c := &config{DB: "pounce-sync.db", Listen: ":8080", Registration: "invite", MaxRecords: 10000, RateIP: 60, RateDevice: 600}
	md, err := toml.DecodeFile(path, c)
	if err != nil {
		return nil, err
	}
	if extra := md.Undecoded(); len(extra) > 0 {
		return nil, fmt.Errorf("%s: unknown key %q", path, extra[0].String())
	}
	if c.MaxRecords < 1 || c.RateIP < 1 || c.RateDevice < 1 {
		return nil, errors.New("max_records, rate_ip and rate_device must be positive integers")
	}
	return c, nil
}

func (c *config) check() error {
	switch {
	case c.Origin == "":
		return errors.New(`origin is required, for example origin = "https://sync.example.org"`)
	case c.Registration != "open" && c.Registration != "invite" && c.Registration != "closed":
		return errors.New("registration must be open, invite or closed")
	case (c.TLSCert == "") != (c.TLSKey == ""):
		return errors.New("set both tls_cert and tls_key, or neither")
	}
	return nil
}
