package bpf

import (
	"io/ioutil"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestBpf_CreateMap(t *testing.T) {
	var testCases = []struct {
		desc        string
		cfg         *MapConfig
		shouldError bool
	}{
		{
			desc:        "fails if no cfg supplied",
			shouldError: true,
		},
		{
			desc: "fails if array with wrong key size",
			cfg: &MapConfig{
				Type:       MapTypeArray,
				KeySize:    16,
				ValueSize:  4,
				MaxEntries: 10,
				Name:       "test_map",
			},
			shouldError: true,
		},
		{
			desc: "array with key size of four",
			cfg: &MapConfig{
				Type:       MapTypeArray,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 10,
				Name:       "test_map",
			},
			shouldError: false,
		},
		{
			desc: "hash with key size of any size",
			cfg: &MapConfig{
				Type:       MapTypeHash,
				KeySize:    16,
				ValueSize:  4,
				MaxEntries: 10,
				Name:       "test_map",
			},
			shouldError: false,
		},
		{
			desc: "fails if hash with key size 0",
			cfg: &MapConfig{
				Type:       MapTypeHash,
				KeySize:    0,
				ValueSize:  4,
				MaxEntries: 10,
				Name:       "test_map",
			},
			shouldError: true,
		},
		{
			desc: "fails if hash with value size 0",
			cfg: &MapConfig{
				Type:       MapTypeHash,
				KeySize:    4,
				ValueSize:  0,
				MaxEntries: 10,
				Name:       "test_map",
			},
			shouldError: true,
		},
	}

	var (
		err error
		fd  int
	)

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			fd, err = CreateMap(tc.cfg)
			if tc.shouldError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			syscall.Close(fd)
		})
	}

	assert.True(t, true)
}

func TestBpf_PinMap_failsIfNotBpfMount(t *testing.T) {
	fd, err := CreateMap(&MapConfig{
		Type:       MapTypeArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
		Name:       "test_map",
	})
	assert.NoError(t, err)
	defer syscall.Close(fd)

	dir, err := ioutil.TempDir("/tmp", "")
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	err = PinMap(fd, dir+"/test_map")
	assert.Error(t, err)
}

func TestBpf_getMapFd(t *testing.T) {
	fd, err := CreateMap(&MapConfig{
		Type:       MapTypeArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
		Name:       "test_map",
	})
	assert.NoError(t, err)
	defer syscall.Close(fd)

	bpfDir, err := ioutil.TempDir("/sys/fs/bpf", "")
	assert.NoError(t, err)
	defer os.RemoveAll(bpfDir)

	err = PinMap(fd, bpfDir+"/test_map")
	assert.NoError(t, err)

	retrievedFd, err := GetMapFd(bpfDir + "/test_map")
	assert.NoError(t, err)
	assert.True(t, retrievedFd > 0)
}

type Key struct {
	field1, field2 uint8
}

type Value struct {
	field1, field2 uint8
}

func TestBpf_lookupElem_doesntErrorIfDoesntExist(t *testing.T) {
	var (
		key   = Key{1, 2}
		value Value
	)

	fd, err := CreateMap(&MapConfig{
		Type:       MapTypeHash,
		KeySize:    uint32(unsafe.Sizeof(key)),
		ValueSize:  uint32(unsafe.Sizeof(value)),
		MaxEntries: 10,
		Name:       "test_map",
	})
	assert.NoError(t, err)
	defer syscall.Close(fd)

	found, err := LookupElemInMap(fd, unsafe.Pointer(&key), unsafe.Pointer(&value))
	assert.NoError(t, err)
	assert.False(t, found)
}
