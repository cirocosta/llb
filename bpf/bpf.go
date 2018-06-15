package bpf

// #include <stdlib.h>
// #include "./bpf.h"
import "C"

import (
	"unsafe"

	"github.com/pkg/errors"
)

type MapType uint32

const (
	MapTypeUnspec MapType = iota
	MapTypeHash
	MapTypeArray
)

// MapConfig specifies the configuration to be used
// when creating a new map.
type MapConfig struct {
	// Type of the map to be created.
	Type MapType
	// Name of the map (can't be bigger than 16 chars).
	Name string
	// KeySize represents the size that each key should
	// have.
	// ps.: if the MapType corresponds to MapTypeArray,
	//      this value must always be equivalent to
	//	4bytes.
	KeySize uint32
	// ValueSize represents the size of the value elements.
	ValueSize uint32
	// MaxEntries determines the maximum number of entries
	// that the map should contain.
	MaxEntries uint32
}

// CreateMap creates an eBPF map using the provided
// configuration of MapConfig.
//
// Supported map types are specified by the MapType
// enum:
//
// - MapTypeHash - BPF_MAP_TYPE_HASH
// - MapTypeArray - BPF_MAP_TYPE_ARRAY
//
// In the case of the second (`MapTypeArray`), the
// KeySize must be 4bytes (uint32) and can't have
// `delete` operations.
func CreateMap(cfg *MapConfig) (fd int, err error) {
	if cfg == nil {
		err = errors.Errorf("cfg can't be nil")
		return
	}

	var nameString = C.CString(cfg.Name)
	defer C.free(unsafe.Pointer(nameString))

	ret, err := C.bpf_create_map(C.enum_bpf_map_type(cfg.Type),
		nameString,
		C.__u32(cfg.KeySize),
		C.__u32(cfg.ValueSize),
		C.__u32(cfg.MaxEntries))
	if err != nil {
		err = errors.Wrapf(err,
			"failed to create map %+v",
			cfg)
		return
	}

	fd = int(ret)

	return
}

// PinMap pins the map pointed by `fd` to a particular
// pathname that must be beneath a bpf virtual filesystem
// mount (`/sys/fs/bpf`).
func PinMap(fd int, path string) (err error) {
	var pathString = C.CString(path)
	defer C.free(unsafe.Pointer(pathString))

	ret, err := C.bpf_obj_pin(C.int(fd), pathString)
	if err != nil || ret != 0 {
		err = errors.Wrapf(err,
			"failed to pin fd %d into map %s",
			fd, path)
		return
	}

	return
}

// GetMapFd retrieves the file descriptor associated with
// the path under `/sys/fs/bpf` of a map that has already
// been created by another program.
func GetMapFd(path string) (fd int, err error) {
	if path == "" {
		err = errors.Errorf("a path must be specified")
		return
	}

	var pathString = C.CString(path)
	defer C.free(unsafe.Pointer(pathString))

	ret, err := C.bpf_obj_get(pathString)
	if err != nil {
		err = errors.Wrapf(err,
			"failed to open map from path %s",
			path)
		return
	}

	if ret < 0 {
		err = errors.Errorf(
			"unexpected error opening map %s",
			path)
		return
	}

	fd = int(ret)

	return
}

// LookupElemInMap looks at the map specified  by a file
// descriptor (`fd`), gathering a value from a given key.
func LookupElemInMap(fd int, key unsafe.Pointer) (value unsafe.Pointer, err error) {
	return
}
