package bpf

import (
	"io/ioutil"
	"os"
	"testing"

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

	bpfDir, err := ioutil.TempDir("/sys/fs/bpf", "")
	assert.NoError(t, err)
	defer os.RemoveAll(bpfDir)

	err = PinMap(fd, bpfDir+"/test_map")
	assert.NoError(t, err)

	retrievedFd, err := GetMapFd(bpfDir + "/test_map")
	assert.NoError(t, err)
	assert.True(t, retrievedFd > 0)
}
