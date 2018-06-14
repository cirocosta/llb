package main

import (
	"github.com/alexflint/go-arg"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	llbBackendsArr    = "llb_backends_arr"
	llbConnectionsMap = "llb_connections_map"
)

type config struct {
	Debug bool `arg:"help:enable debug logs"`
}

var (
	version string = "dev"
	args           = &config{
		Debug: false,
	}
)

func main() {
	arg.MustParse(args)

	log.Info().
		Str("version", version).
		Interface("args", args).
		Msg("initializing")

	if args.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}
