package grpc

import (
	"context"
	"fmt"

	"github.com/mennanov/fmutils"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/streams"
	"github.com/aquasecurity/tracee/pkg/version"
)

type TraceeService struct {
	pb.UnimplementedTraceeServiceServer
	tracee *tracee.Tracee
}

func (s *TraceeService) StreamEvents(in *pb.StreamEventsRequest, grpcStream pb.TraceeService_StreamEventsServer) error {
	var stream *streams.Stream
	var err error

	if len(in.Policies) == 0 {
		stream = s.tracee.SubscribeAll()
	} else {
		stream, err = s.tracee.Subscribe(in.Policies)
		if err != nil {
			return err
		}
	}
	defer s.tracee.Unsubscribe(stream)

	mask := fmutils.NestedMaskFromPaths(in.GetMask().GetPaths())

	for e := range stream.ReceiveEvents() {
		// TODO: this conversion is temporary, we will use the new event structure
		// on tracee internals, so the event received by the stream will already be a proto
		// eventProto, err := convertTraceeEventToProto(e)
		// if err != nil {
		// 	logger.Errorw("error can't create event proto: " + err.Error())
		// 	continue
		// }

		mask.Filter(e)

		err = grpcStream.Send(&pb.StreamEventsResponse{Event: e})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *TraceeService) EnableEvent(ctx context.Context, in *pb.EnableEventRequest) (*pb.EnableEventResponse, error) {
	err := s.tracee.EnableEvent(in.Name)
	if err != nil {
		return nil, err
	}

	return &pb.EnableEventResponse{}, nil
}

func (s *TraceeService) DisableEvent(ctx context.Context, in *pb.DisableEventRequest) (*pb.DisableEventResponse, error) {
	err := s.tracee.DisableEvent(in.Name)
	if err != nil {
		return nil, err
	}

	return &pb.DisableEventResponse{}, nil
}

func (s *TraceeService) GetEventDefinition(ctx context.Context, in *pb.GetEventDefinitionRequest) (*pb.GetEventDefinitionResponse, error) {
	definitions, err := getDefinitions(in)
	if err != nil {
		return nil, err
	}

	out := make([]*pb.EventDefinition, 0, len(definitions))

	for _, d := range definitions {
		ed := convertDefinitionToProto(d)
		out = append(out, ed)
	}

	return &pb.GetEventDefinitionResponse{
		Definitions: out,
	}, nil
}

func (s *TraceeService) GetVersion(ctx context.Context, in *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	return &pb.GetVersionResponse{Version: version.GetVersion()}, nil
}

func getDefinitions(in *pb.GetEventDefinitionRequest) ([]events.Definition, error) {
	if in.Name == "" {
		return events.Core.GetDefinitions(), nil
	}

	id, ok := events.Core.GetDefinitionIDByName(in.Name)
	if !ok {
		return nil, fmt.Errorf("event %s not found", in.Name)
	}

	return []events.Definition{events.Core.GetDefinitionByID(id)}, nil
}

func convertDefinitionToProto(d events.Definition) *pb.EventDefinition {
	v := &pb.Version{
		Major: d.GetVersion().Major(),
		Minor: d.GetVersion().Minor(),
		Patch: d.GetVersion().Patch(),
	}

	return &pb.EventDefinition{
		Id:          int32(d.GetID()),
		Name:        d.GetName(),
		Version:     v,
		Description: d.GetDescription(),
		Tags:        d.GetSets(),
		// threat description is empty because it is the same as the event definition description
		Threat: getThreat("", d.GetProperties()),
	}
}

func getThreat(description string, metadata map[string]interface{}) *pb.Threat {
	if metadata == nil {
		return nil
	}
	// if metadata doesn't contain severity, it's not a threat,
	// severity is set when we have an event created from a signature
	// pkg/ebpf/fiding.go
	// pkg/cmd/initialize/sigs.go
	_, ok := metadata["Severity"]
	if !ok {
		return nil
	}

	var (
		mitreTactic        string
		mitreTechniqueId   string
		mitreTechniqueName string
		name               string
	)

	if _, ok := metadata["Category"]; ok {
		if val, ok := metadata["Category"].(string); ok {
			mitreTactic = val
		}
	}

	if _, ok := metadata["external_id"]; ok {
		if val, ok := metadata["external_id"].(string); ok {
			mitreTechniqueId = val
		}
	}

	if _, ok := metadata["Technique"]; ok {
		if val, ok := metadata["Technique"].(string); ok {
			mitreTechniqueName = val
		}
	}

	if _, ok := metadata["signatureName"]; ok {
		if val, ok := metadata["signatureName"].(string); ok {
			name = val
		}
	}

	properties := make(map[string]string)

	for k, v := range metadata {
		if k == "Category" ||
			k == "external_id" ||
			k == "Technique" ||
			k == "Severity" ||
			k == "signatureName" {
			continue
		}

		properties[k] = fmt.Sprint(v)
	}

	return &pb.Threat{
		Description: description,
		Mitre: &pb.Mitre{
			Tactic: &pb.MitreTactic{
				Name: mitreTactic,
			},
			Technique: &pb.MitreTechnique{
				Id:   mitreTechniqueId,
				Name: mitreTechniqueName,
			},
		},
		Severity:   getSeverity(metadata),
		Name:       name,
		Properties: properties,
	}
}

func getSeverity(metadata map[string]interface{}) pb.Severity {
	switch metadata["Severity"].(int) {
	case 0:
		return pb.Severity_INFO
	case 1:
		return pb.Severity_LOW
	case 2:
		return pb.Severity_MEDIUM
	case 3:
		return pb.Severity_HIGH
	case 4:
		return pb.Severity_CRITICAL
	}

	return -1
}
