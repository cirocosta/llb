package main

import (
	"encoding/binary"

	"github.com/alexflint/go-arg"
	"github.com/cirocosta/llb/bpf"
	"github.com/cirocosta/llb/llb"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	mapLlbHashBackends = "/sys/fs/bpf/tc/globals/llb_h_bnx"
)

type config struct {
	Debug    bool     `arg:"help:enable debug logs"`
	Backends []string `arg:"--backend,help:address (including ports) to route to"`
}

var (
	version = "dev"
	args    = &config{
		Debug:    false,
		Backends: []string{},
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

	fd, err := bpf.GetMapFd(mapLlbHashBackends)
	must(err)

	lb := llb.New(&llb.Config{
		BackendsMapFd: fd,
	})

	err = lb.AddBackendToMap(&llb.Backend{
		Address: binary.LittleEndian.Uint32([]byte{172, 17, 0, 3}),
		Port:    8000,
	})
	must(err)
}
