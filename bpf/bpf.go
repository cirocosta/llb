package bpf

// #include "./bpf.h"
import "C"

import (
	"unsafe"

	"github.com/pkg/errors"
)

func GetMapFd(path string) (fd int, err error) {
	if path == "" {
		err = errors.Error("a path must be specified")
		return
	}

	var pathString = C.CString(path)
	defer C.free(unsafe.Pointer(pathString))

	fd, err = C.bpf_obj_get(pathString)
	if err != nil {
		err = errors.Wrapf(err,
			"failed to open map from path %s",
			path)
		return
	}

	if fd < 0 {
		err = errors.Errorf(
			"unexpected error opening map %s",
			path)
		return
	}

	return
}
