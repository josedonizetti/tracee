package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareBuffers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		flags          []string
		expectedReturn BuffersConfig
		expectedError  string
	}{
		// default values (no flags)
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       GetDefaultPerfBufferSize(),
					Blobs:        GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 10_000,
			},
		},
		// valid single flag
		{
			testName: "valid kernel.events",
			flags:    []string{"kernel.events=2048"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       2048,
					Blobs:        GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 10_000,
			},
		},
		{
			testName: "valid pipeline",
			flags:    []string{"pipeline=4000"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       GetDefaultPerfBufferSize(),
					Blobs:        GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 4000,
			},
		},
		{
			testName: "valid kernel.blobs",
			flags:    []string{"kernel.blobs=512"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       GetDefaultPerfBufferSize(),
					Blobs:        512,
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 10_000,
			},
		},
		{
			testName: "valid kernel.control-plane",
			flags:    []string{"kernel.control-plane=256"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       GetDefaultPerfBufferSize(),
					Blobs:        GetDefaultPerfBufferSize(),
					ControlPlane: 256,
				},
				Pipeline: 10_000,
			},
		},
		// valid multiple flags
		{
			testName: "valid multiple flags",
			flags:    []string{"kernel.events=2048", "pipeline=5000"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       2048,
					Blobs:        GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 5000,
			},
		},
		{
			testName: "valid all flags",
			flags:    []string{"kernel.events=2048", "pipeline=4000", "kernel.blobs=512", "kernel.control-plane=256"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       2048,
					Blobs:        512,
					ControlPlane: 256,
				},
				Pipeline: 4000,
			},
		},
		{
			testName: "valid flags in different order",
			flags:    []string{"kernel.blobs=512", "kernel.control-plane=256", "kernel.events=2048", "pipeline=40000"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       2048,
					Blobs:        512,
					ControlPlane: 256,
				},
				Pipeline: 40_000,
			},
		},
		// valid duplicate flags (last one wins)
		{
			testName: "valid duplicate flags",
			flags:    []string{"kernel.events=2048", "kernel.events=4096"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       4096,
					Blobs:        GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 10_000,
			},
		},
		// invalid flag format (missing =)
		{
			testName:       "invalid flag format missing equals",
			flags:          []string{"kernel.events"},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffers flag: 'kernel.events', use 'trace man buffers' for more info",
		},
		{
			testName:       "invalid flag format missing equals with value",
			flags:          []string{"kernel.events2048"},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffers flag: 'kernel.events2048', use 'trace man buffers' for more info",
		},
		{
			testName:       "invalid flag format empty value",
			flags:          []string{"kernel.events="},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffers flag: 'kernel.events=', use 'trace man buffers' for more info",
		},
		// invalid flag name
		{
			testName:       "invalid flag name",
			flags:          []string{"invalid-flag=2048"},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffers flag: 'invalid-flag', use 'trace man buffers' for more info",
		},
		{
			testName:       "invalid flag name with typo",
			flags:          []string{"kernel.event=2048"},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffers flag: 'kernel.event', use 'trace man buffers' for more info",
		},
		{
			testName:       "invalid flag name empty",
			flags:          []string{"=2048"},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffers flag: '=2048', use 'trace man buffers' for more info",
		},
		// invalid flag value (non-numeric) - note: parseInt returns 0, doesn't error
		{
			testName:       "invalid flag value non-numeric",
			flags:          []string{"kernel.events=invalid"},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: kernel.events value must be a positive integer, use 'trace man buffers' for more info",
		},
		{
			testName:       "invalid flag value negative",
			flags:          []string{"kernel.events=-2048"},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: kernel.events value can't be negative or zero, use 'trace man buffers' for more info",
		},
		// valid edge cases
		{
			testName:       "valid zero value",
			flags:          []string{"kernel.events=0"},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: kernel.events value can't be negative or zero, use 'trace man buffers' for more info",
		},
		{
			testName: "valid large value",
			flags:    []string{"kernel.events=999999"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       999999,
					Blobs:        GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 10_000,
			},
		},
		// mixed valid and invalid
		{
			testName:       "mixed valid and invalid flag name",
			flags:          []string{"kernel.events=2048", "invalid-flag=4096"},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffers flag: 'invalid-flag', use 'trace man buffers' for more info",
		},
		{
			testName:       "mixed valid and invalid format",
			flags:          []string{"kernel.events=2048", "pipeline"},
			expectedReturn: BuffersConfig{},
			expectedError:  "flags.PrepareBuffers: invalid buffers flag: 'pipeline', use 'trace man buffers' for more info",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			buffers, err := PrepareBuffers(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn.Kernel.Events, buffers.Kernel.Events)
				assert.Equal(t, tc.expectedReturn.Kernel.Blobs, buffers.Kernel.Blobs)
				assert.Equal(t, tc.expectedReturn.Kernel.ControlPlane, buffers.Kernel.ControlPlane)
				assert.Equal(t, tc.expectedReturn.Pipeline, buffers.Pipeline)
			}
		})
	}
}

func TestBuffersConfig_flags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName      string
		config        BuffersConfig
		expectedFlags []string
	}{
		{
			testName:      "empty config returns empty flags",
			config:        BuffersConfig{},
			expectedFlags: []string{},
		},
		{
			testName: "kernel.events only",
			config: BuffersConfig{
				Kernel: KernelBuffersConfig{Events: 2048},
			},
			expectedFlags: []string{"kernel.events=2048"},
		},
		{
			testName: "kernel.blobs only",
			config: BuffersConfig{
				Kernel: KernelBuffersConfig{Blobs: 512},
			},
			expectedFlags: []string{"kernel.blobs=512"},
		},
		{
			testName: "kernel.control-plane only",
			config: BuffersConfig{
				Kernel: KernelBuffersConfig{ControlPlane: 256},
			},
			expectedFlags: []string{"kernel.control-plane=256"},
		},
		{
			testName: "pipeline only",
			config: BuffersConfig{
				Pipeline: 4000,
			},
			expectedFlags: []string{"pipeline=4000"},
		},
		{
			testName: "all flags set",
			config: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       2048,
					Blobs:        512,
					ControlPlane: 256,
				},
				Pipeline: 4000,
			},
			expectedFlags: []string{
				"kernel.events=2048",
				"kernel.blobs=512",
				"kernel.control-plane=256",
				"pipeline=4000",
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			flags := tc.config.flags()
			assert.Equal(t, tc.expectedFlags, flags)
		})
	}
}
