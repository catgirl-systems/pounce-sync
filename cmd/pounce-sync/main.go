package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pounce-sync/internal/api"
	"pounce-sync/internal/store"
)

const usage = "usage: pounce-sync [-config pounce-sync.toml] [serve | invite [-ttl 168h] | stats | backup <path>]"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pounce-sync:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("pounce-sync", flag.ContinueOnError)
	path := fs.String("config", "pounce-sync.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmd, args := "serve", fs.Args()
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	cmds := map[string]func(*config, []string) error{"serve": serve, "invite": invite, "stats": stats, "backup": backup}
	if cmds[cmd] == nil {
		return errors.New(usage)
	}
	c, err := loadConfig(*path)
	if err != nil {
		return err
	}
	return cmds[cmd](c, args)
}

// withStore opens the database for fn and closes it after.
func withStore(c *config, fn func(*store.Store) error) error {
	st, err := store.Open(c.DB)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(st)
}

func serve(c *config, _ []string) error {
	if err := c.check(); err != nil {
		return err
	}
	return withStore(c, func(st *store.Store) error { return listen(c, st) })
}

func listen(c *config, st *store.Store) error {
	cfg := api.Config{Origin: c.Origin, Registration: c.Registration, MaxRecords: c.MaxRecords,
		RateIP: c.RateIP, RateDevice: c.RateDevice, RealIPHeader: c.RealIPHeader}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// a signal ends pending long-polls with an empty reply, so Shutdown is prompt.
	cfg.Stop = ctx.Done()

	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if err := st.Sweep(ctx, now); err != nil && ctx.Err() == nil {
					slog.Error("sweep", "err", err)
				}
			}
		}
	}()

	// write timeout stays above the 30 s long-poll; ErrorLog is discarded
	// because net/http logs client addresses (TLS handshake errors).
	srv := &http.Server{
		Addr:              c.Listen,
		Handler:           api.New(cfg, st),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	errc := make(chan error, 1)
	go func() {
		if c.TLSCert != "" {
			errc <- srv.ListenAndServeTLS(c.TLSCert, c.TLSKey)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	slog.Info("listening", "addr", srv.Addr, "registration", cfg.Registration)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		srv.Close()
	}
	return nil
}

func invite(c *config, args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	ttl := fs.Duration("ttl", 168*time.Hour, "how long the invite stays valid")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *ttl <= 0 {
		return errors.New(usage)
	}
	return withStore(c, func(st *store.Store) error {
		tok, err := st.CreateInvite(context.Background(), *ttl)
		if err == nil {
			fmt.Println(tok)
		}
		return err
	})
}

func stats(c *config, _ []string) error {
	return withStore(c, func(st *store.Store) error {
		accounts, records, size, err := st.Stats(context.Background())
		if err == nil {
			fmt.Printf("accounts %d\nrecords %d\nbytes %d\n", accounts, records, size)
		}
		return err
	})
}

func backup(c *config, args []string) error {
	if len(args) != 1 {
		return errors.New(usage)
	}
	return withStore(c, func(st *store.Store) error { return st.Backup(context.Background(), args[0]) })
}
