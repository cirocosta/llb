package llb

import (
	"unsafe"

	"github.com/cirocosta/llb/bpf"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// LlbConfig is the configuration to be used by the instantiator
// (NewLlb) to create an Llb instance.
type LlbConfig struct {
	// BackendsMapFd corresponds to the file descriptor
	// that corresponds to the bpf map that keeps track
	// of possible backends to connect to.
	//
	// ps.: this file must already exist before Llb is
	// launched, i.e., the map must have already been
	// created and pinned.
	BackendsMapFd int
}

// Llb keeps track of backends state as well as providing ways of
// configuring them.
type Llb struct {
	LlbConfig
	logger zerolog.Logger

	// backends keeps track of the backends configured
	// for use.
	//
	// This is meant to be synced on every run of llb
	// and updated atomically.
	backends map[uint32]*Backend
}

// NewLLb instantiates a new Llb instance following the configuration
// passed via LlbConfig.
func NewLlb(cfg *LlbConfig) (l Llb) {
	l.LlbConfig = *cfg
	l.logger = log.With().
		Str("from", "llb").
		Logger()
	return
}

// GetBackendsFromMap iterates over the bpf map and gathers
// the whole state that corresponds to the loaded Backend elements.
//
// TODO add iteration to bpf module
func (l *Llb) GetBackendsFromMap() (backends map[uint32]*Backend, err error) {
	return
}

// AddBackendToMap adds a backend to the bpf that knows about
// backends to route connections to.
func (l *Llb) AddBackendToMap(backend *Backend) (err error) {
	// TODO testing
	var key uint32 = 1
	err = bpf.CreateOrUpdateElemInMap(l.BackendsMapFd,
		unsafe.Pointer(&key),
		unsafe.Pointer(backend))
	if err != nil {
		err = errors.Wrapf(err,
			"failed to add backend %+v to map",
			backend)
		return
	}

	return
}

// RemoveBackendFromMap removes a backend from the bpf map.
func (l *Llb) RemoveBackendFromMap(backend *Backend) (err error) {
	return
}
