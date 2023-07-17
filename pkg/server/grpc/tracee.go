package grpc

import (
	"context"
	"errors"

	"github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/version"
	pb "github.com/aquasecurity/tracee/types/api/v1beta1"
	"github.com/aquasecurity/tracee/types/trace"

	"github.com/mennanov/fmutils"
)

type TraceeService struct {
	pb.UnimplementedTraceeServiceServer
	tracee *ebpf.Tracee
}

func (s *TraceeService) GetEventMetadata(context.Context, *pb.GetEventMetadataRequest) (*pb.GetEventMetadataResponse, error) {
	return nil, nil
}

func (s *TraceeService) StreamEvents(in *pb.StreamEventsRequest, grpcStream pb.TraceeService_StreamEventsServer) error {
	stream, err := s.tracee.Subscribe(in.Policies)
	if err != nil {
		return err
	}
	defer s.tracee.Unsubscribe(stream)

	mask := fmutils.NestedMaskFromPaths(in.GetMask().GetPaths())

	for e := range stream.ReceiveEvents() {
		eventProto := convertTraceeEventToProto(e)
		mask.Filter(eventProto)
		grpcStream.Send(eventProto)
	}

	return nil
}

func (s *TraceeService) EnablePolicy(ctx context.Context, in *pb.EnablePolicyRequest) (*pb.EnablePolicyResponse, error) {
	s.tracee.EnablePolicy(ctx, in.PolicyName)
	return &pb.EnablePolicyResponse{}, nil
}

func (s *TraceeService) DisablePolicy(ctx context.Context, in *pb.DisablePolicyRequest) (*pb.DisablePolicyResponse, error) {
	s.tracee.DisablePolicy(ctx, in.PolicyName)
	return &pb.DisablePolicyResponse{}, nil
}

func (s *TraceeService) EnablePolicyRule(ctx context.Context, in *pb.EnablePolicyRuleRequest) (*pb.EnablePolicyRuleResponse, error) {
	id, ok := events.Core.GetDefinitionIDByName(in.RuleId)
	if !ok {
		return nil, errors.New("event not found")
	}
	s.tracee.EnableEvent(ctx, in.PolicyName, id)

	return &pb.EnablePolicyRuleResponse{}, nil
}

func (s *TraceeService) DisablePolicyRule(ctx context.Context, in *pb.DisablePolicyRuleRequest) (*pb.DisablePolicyRuleResponse, error) {
	id, ok := events.Core.GetDefinitionIDByName(in.RuleId)
	if !ok {
		return nil, errors.New("event not found")
	}
	s.tracee.DisableEvent(ctx, in.PolicyName, id)

	return &pb.DisablePolicyRuleResponse{}, nil
}

func (s *TraceeService) GetVersion(ctx context.Context, in *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	return &pb.GetVersionResponse{Version: version.GetVersion()}, nil
}

func convertTraceeEventToProto(e trace.Event) *pb.Event {
	return &pb.Event{
		Id:        int64(e.EventID),
		Name:      e.EventName,
		Timestamp: int64(e.Timestamp),
		Metadata:  nil,
		Context: &pb.Context{
			// ProcessorId: uint32(e.ProcessorId),
			Process: &pb.Process{
				//ExecutionTime
				// Binary:       ,
				Pid: int32(e.ProcessID),
				// NamespacePid: int64(e.PIDNS),
				UserId: uint32(e.UserID),
				// UserName
				// Ancestors
				Threads: []*pb.Thread{
					{
						// StartTime:
						// Name
						Tid: int64(e.ThreadID),
						// NamespaceTid:
						// MountNamespaceId
						// PidNamespaceId
						// UtsName
						Syscall: e.Syscall,
						// Compat
						// UserStackTrace
						// Capabilities
					},
				},
			},
			Container: &pb.Container{
				Id:   e.ContainerID,
				Name: e.Container.Name,
				Image: &pb.Container_Image{
					Name:   e.Container.ImageName,
					Digest: e.Container.ImageDigest,
				},
			},
			Pod: &pb.Pod{
				Name:      e.Kubernetes.PodName,
				Namespace: e.Kubernetes.PodNamespace,
				Uid:       e.Kubernetes.PodUID,
				// Sandbox
			},
		},
		Data: &pb.Data{
			ReturnValue: int64(e.ReturnValue),
			Arguments:   getArguments(e.Args),
		},
		Tracee: &pb.Tracee{
			MatchedPolicies: e.MatchedPoliciesUser,
		},
	}
}

func getArguments(args []trace.Argument) []*pb.Argument {
	if len(args) == 0 {
		return nil
	}

	arguments := make([]*pb.Argument, 0, len(args))
	for _, arg := range args {
		arguments = append(arguments, &pb.Argument{
			//Value: -- como fazer com o valor?
			ArgMetada: &pb.ArgMeta{
				Name: arg.Name,
				Type: arg.Type,
			},
		})
	}

	return arguments
}
