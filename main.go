package main

import (
	"github.com/alexflint/go-arg"
	"github.com/cirocosta/llb/bpf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	llbBackendsArr    = "/sys/fs/bpf/tc/globals/llb_backends_arr"
	llbConnectionsMap = "/sys/fs/bpf/tc/globals/llb_connections_map"
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

func must(err error) {
	if err == nil {
		return
	}

	log.Fatal().
		Err(err).
		Msg("stopping execution")
}

func main() {
	arg.MustParse(args)

	log.Info().
		Str("version", version).
		Interface("args", args).
		Msg("initializing")

	if args.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	fd, err := bpf.GetMapFd(llbBackendsArr)
	must(err)

	log.Info().Int("fd", fd).Msg("fd retrieved")
}
