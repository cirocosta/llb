package bpf

import (
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
