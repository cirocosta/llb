package bpf

// #include <stdlib.h>
// #include "./bpf.h"
import "C"

import (
	"unsafe"

	"github.com/pkg/errors"
)

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
