package types

import (
	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
	"google.golang.org/protobuf/proto"
)

// Event wrappers a pb.Event with additional metadata
type Event struct {
	*pb.Event
	PoliciesVersion       uint16 `json:"-"`
	MatchedPoliciesKernel uint64 `json:"-"`
	MatchedPoliciesUser   uint64 `json:"-"`
}

func (e *Event) Proto() *pb.Event {
	return e.Event
}

// Origin derive the EventOrigin of a trace.Event
func (e *Event) Origin() trace.EventOrigin {
	// TODO: check for nulls
	if e.GetContext().GetProcess().GetThread().GetCompat() {
		return trace.ContainerOrigin
	}
	if e.GetContext().GetContainer().GetId() != "" {
		return trace.ContainerInitOrigin
	}
	return trace.HostOrigin
}

func (e *Event) ToProtocol() protocol.Event {
	return protocol.Event{
		Headers: protocol.EventHeaders{
			Selector: protocol.Selector{
				Name:   e.Name,
				Origin: string(e.Origin()),
				Source: "tracee",
			},
		},
		Payload: e,
	}
}

func Clone(e *Event) *Event {
	return &Event{
		Event:                 proto.Clone(e.Event).(*pb.Event),
		PoliciesVersion:       e.PoliciesVersion,
		MatchedPoliciesKernel: e.MatchedPoliciesKernel,
		MatchedPoliciesUser:   e.MatchedPoliciesUser,
	}
}
