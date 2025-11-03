package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/datastores/dns"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
)

func TestPrepareStores(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		flags          []string
		expectedReturn StoresConfig
		expectedError  string
	}{
		// default values (no flags)
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		// valid single DNS flags
		{
			testName: "valid dns.enabled",
			flags:    []string{"dns.enabled"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid dns.max-entries",
			flags:    []string{"dns.max-entries=2048"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: 2048,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		// valid single Process flags
		{
			testName: "valid process.enabled",
			flags:    []string{"process.enabled"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid process.max-processes",
			flags:    []string{"process.max-processes=100"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: 100,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid process.max-threads",
			flags:    []string{"process.max-threads=50"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   50,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid process.source=none",
			flags:    []string{"process.source=none"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid process.source=events",
			flags:    []string{"process.source=events"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "events",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid process.source=signals",
			flags:    []string{"process.source=signals"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "signals",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid process.source=both",
			flags:    []string{"process.source=both"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "both",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid process.use-procfs",
			flags:    []string{"process.use-procfs"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		// valid multiple flags
		{
			testName: "valid multiple DNS flags",
			flags:    []string{"dns.enabled", "dns.max-entries=4096"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true,
					MaxEntries: 4096,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid multiple Process flags",
			flags:    []string{"process.enabled", "process.max-processes=200", "process.max-threads=100"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true,
					MaxProcesses: 200,
					MaxThreads:   100,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid all flags",
			flags:    []string{"dns.enabled", "dns.max-entries=2048", "process.enabled", "process.max-processes=150", "process.max-threads=75", "process.source=both", "process.use-procfs"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true,
					MaxEntries: 2048,
				},
				Process: ProcessConfig{
					Enabled:      true,
					MaxProcesses: 150,
					MaxThreads:   75,
					Source:       "both",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid flags in different order",
			flags:    []string{"process.use-procfs", "dns.max-entries=512", "process.source=events", "process.max-threads=25"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: 512,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   25,
					Source:       "events",
					Procfs:       true,
				},
			},
		},
		// invalid flag format
		{
			testName: "invalid flag format missing equals with value",
			flags:    []string{"dns.enabledtrue"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.PrepareStores: invalid stores flag: dns.enabledtrue, use 'trace man stores' for more info",
		},
		{
			testName: "invalid dns.max-entries missing value",
			flags:    []string{"dns.max-entries"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.PrepareStores: invalid stores flag: dns.max-entries, use 'trace man stores' for more info",
		},
		{
			testName: "invalid dns.max-entries empty value",
			flags:    []string{"dns.max-entries="},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.parseSize: invalid stores flag: dns.max-entries=, use 'trace man stores' for more info",
		},
		// invalid flag name
		{
			testName: "invalid flag name",
			flags:    []string{"invalid-flag=true"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.PrepareStores: invalid stores flag: invalid-flag=true, use 'trace man stores' for more info",
		},
		{
			testName: "invalid flag name with typo",
			flags:    []string{"dns.enable=true"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.PrepareStores: invalid stores flag: dns.enable=true, use 'trace man stores' for more info",
		},
		// invalid DNS values
		{
			testName: "invalid dns.max-entries value non-numeric",
			flags:    []string{"dns.max-entries=invalid"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.parseSize: invalid stores flag: dns.max-entries=invalid, use 'trace man stores' for more info",
		},
		{
			testName: "invalid dns.max-entries value negative",
			flags:    []string{"dns.max-entries=-100"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.parseSize: invalid stores flag: dns.max-entries=-100, use 'trace man stores' for more info",
		},
		// invalid Process values
		{
			testName: "invalid process.max-processes value non-numeric",
			flags:    []string{"process.max-processes=invalid"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.parseSize: invalid stores flag: process.max-processes=invalid, use 'trace man stores' for more info",
		},
		{
			testName: "invalid process.max-threads value non-numeric",
			flags:    []string{"process.max-threads=invalid"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.parseSize: invalid stores flag: process.max-threads=invalid, use 'trace man stores' for more info",
		},
		// valid edge cases
		{
			testName: "invalid zero values",
			flags:    []string{"dns.max-entries=0", "process.max-processes=0", "process.max-threads=0"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.parseSize: invalid stores flag: dns.max-entries=0, use 'trace man stores' for more info",
		},
		{
			testName: "valid large values",
			flags:    []string{"dns.max-entries=999999", "process.max-processes=999999", "process.max-threads=999999"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: 999999,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: 999999,
					MaxThreads:   999999,
					Source:       "none",
					Procfs:       true,
				},
			},
		},
		// mixed valid and invalid
		{
			testName: "mixed valid and invalid flag name",
			flags:    []string{"dns.enabled", "invalid-flag=value"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      false,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "none",
					Procfs:       true,
				},
			},
			expectedError: "flags.PrepareStores: invalid stores flag: invalid-flag=value, use 'trace man stores' for more info",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			stores, err := PrepareStores(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn, stores)
			}
		})
	}
}
