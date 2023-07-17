package ebpf

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/utils"
)

type policyManager struct {
	active uint64
	mutex  sync.Mutex
}

func (s *policyManager) IsPolicyDisabled(eventPolicies uint64) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return (s.active & eventPolicies) == 0
}

func (s *policyManager) Enable(policyId int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	utils.SetBit(&s.active, uint(policyId))
}

func (s *policyManager) Disable(policyId int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	utils.ClearBit(&s.active, uint(policyId))
}
