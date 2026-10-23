// connaio-relay is the server's end of a Connaio reverse tunnel, run as an ordinary user:
// connaio-relay -c <config.json>, the config as component/relay's Config. With -check it only checks
// that the config can be served (its ports free) and exits; -version prints its Version.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/metacubex/mihomo/component/relay"
)

func main() {
	path := flag.String("c", "", "config file (JSON)")
	check := flag.Bool("check", false, "check the config can be served, then exit")
	version := flag.Bool("version", false, "print the version (the executable's sha256) and exit")
	flag.Parse()
	v := relay.Version() // hashed now: a reinstall replaces the file this process runs from
	if *version {
		fmt.Println(v)
		return
	}
	b, err := os.ReadFile(*path)
	if err != nil {
		log.Fatal(err)
	}
	var cfg relay.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("%s: %v", *path, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *check {
		stop() // a done context: Run sets everything up and returns
	}
	if err := relay.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}
