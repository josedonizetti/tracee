package ebpf

import (
	"context"
	"sync"

	"github.com/aquasecurity/tracee/types/trace"
)

type Stream interface {
	ReceiveEvents() <-chan trace.Event
}

type stream struct {
	policyMask uint64
	events     chan trace.Event
}

func (s *stream) sendEvent(ctx context.Context, e *trace.Event) {
	if (e.MatchedPoliciesUser & s.policyMask) == 0 {
		return
	}

	select {
	case s.events <- *e:
	case <-ctx.Done():
	default:
		// log drop
	}
}

func (s *stream) ReceiveEvents() <-chan trace.Event {
	return s.events
}

type streamManager struct {
	subscribers map[*stream]struct{}
	mutex       sync.Mutex
}

func newStreamManager() *streamManager {
	return &streamManager{
		subscribers: make(map[*stream]struct{}),
		mutex:       sync.Mutex{},
	}
}

func (m *streamManager) addStream(s *stream) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.subscribers[s] = struct{}{}
}

func (m *streamManager) removeStream(s *stream) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.subscribers, s)
}

func (m *streamManager) notify(ctx context.Context, e *trace.Event) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	for c := range m.subscribers {
		c.sendEvent(ctx, e)
	}
}
