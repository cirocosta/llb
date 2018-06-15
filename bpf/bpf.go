// Package bpf implements a set of methods to facilitate using the
// `bpf(2)` syscall.
//
// Given that the compilation of the ebpf c-like syntax is
// meant to be done beforehand (we're relying on tc object-file
// mode), this tiny library only deals with maps - loading
// is done directly with `tc` and compilation with `clang`.
package bpf

// #include <stdlib.h>
// #include "./bpf.h"
import "C"

import (
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

// MapType acts as an enumeration of the BPF_MAP_TYPE_*
// variables that can be used with the `BPF_MAP_CREATE` command
// of the `bpf(2)` syscall.
type MapType uint32

const (
	// MapTypeUnspec corresponds to BPF_MAP_TYPE_UNSPEC,
	// reserving 0 as an invalid map type.
	MapTypeUnspec MapType = iota
	// MapTypeHash corresponds to BPF_MAP_TYPE_HASH, an
	// implementation of hash-tables that can have
	// arbitrary key and value sizes.
	MapTypeHash
	// MapTypeArray corresponds to BPF_MAP_TYPE_ARRAY, an
	// implementation of an array that has all of its
	// elements initialized.
	//
	// It doesn't support `delete` operations and the
	// key size must always correspond to 4 octets.
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
//
// Once the map has been created, the returned `fd` can
// be used to perform map operations.
//
// To have it available in the bpf fs, make use of
// `PinMap` (otherwise, it'll not exist anymore after
// the process that created it exits).
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

// CreateOrUpdateElemInMap creates or updates an element (key/value pair)
// in a specified map.
//
// It makes use of the underlying `bpf(2)` syscall with BPF_MAP_UPDATE_ELEM
// having the BPF_ANY flag set.
func CreateOrUpdateElemInMap(fd int, key, value unsafe.Pointer) (err error) {
	_, err = C.bpf_map_update_elem(C.int(fd), key, value, C.BPF_ANY)
	if err != nil {
		err = errors.Wrapf(err,
			"failed to create or update element in map %d", fd)
		return
	}

	return
}

// DeleteElemFromMap looks up and delete an element by key in a specified map.
// If the element doesn't exist or an element has been indeed deleted,
// no error is returned.
func DeleteElemFromMap(fd int, key unsafe.Pointer) (err error) {
	_, err = C.bpf_map_delete_elem(C.int(fd), key)
	if err != nil {
		errno := err.(syscall.Errno)
		if errno == C.ENOENT {
			err = nil
			return
		}

		err = errors.Wrapf(err,
			"failed to delete elem from map %d", fd)
		return
	}

	return
}

// LookupElemInMap looks at the map specified  by a file
// descriptor (`fd`), gathering a value from a given key.
func LookupElemInMap(fd int, key, value unsafe.Pointer) (found bool, err error) {
	_, err = C.bpf_map_lookup_elem(C.int(fd), key, value)
	if err != nil {
		errno := err.(syscall.Errno)
		if errno == C.ENOENT {
			err = nil
			return
		}

		err = errors.Wrapf(err,
			"failed to lookup elem in map %d", fd)
		return
	}

	found = true
	return
}
