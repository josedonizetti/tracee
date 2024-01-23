package sorting

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/types"
)

// Events queue with the ability to follow if it was updated since last check and insertion by time specific for CPU
// queue ordering
type cpuEventsQueue struct {
	eventsQueue
	IsUpdated bool
}

// InsertByTimestamp insert new event to the queue in the right position according to its timestamp
func (cq *cpuEventsQueue) InsertByTimestamp(newEvent *types.Event) error {
	newNode, err := cq.pool.Alloc(newEvent)
	if err != nil {
		cq.pool.Reset()
	}

	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	eventTimestamp := cq.tail.event.Timestamp.AsTime()
	newEventTimestamp := newEvent.Timestamp.AsTime()

	if cq.tail != nil &&
		eventTimestamp.After(newEventTimestamp) {
		// We have a fresh event with a timestamp older than the last event received in this cpu's queue.
		// This can only happen if this fresh event is a syscall event (for which we take the entry timestamp) which
		// called some internal kernel functions (that are also traced). Insert the syscall event before these other
		// events
		insertLocation := cq.tail
		for insertLocation.next != nil {
			ts := insertLocation.next.event.Timestamp.AsTime()
			if ts.Before(newEvent.Timestamp.AsTime()) {
				break
			}
			if insertLocation.next == insertLocation {
				if err != nil {
					err = errfmt.Errorf("encountered node with self reference at next: %v", err)
				}
			}
			insertLocation = insertLocation.next
		}
		cq.insertAfter(newNode, insertLocation)
	} else {
		cq.put(newNode)
	}
	return errfmt.WrapError(err)
}

// insertAfter insert new event to the queue after another node
// This is useful if new node place is not at the end of the queue but before it
func (cq *cpuEventsQueue) insertAfter(newNode *eventNode, baseEvent *eventNode) {
	if baseEvent.next != nil {
		baseEvent.next.previous = newNode
	}
	newNode.previous = baseEvent
	newNode.next, baseEvent.next = baseEvent.next, newNode
	if cq.head == baseEvent {
		cq.head = newNode
	}
}
