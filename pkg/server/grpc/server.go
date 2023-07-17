package grpc

import (
	"context"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/logger"
	pb "github.com/aquasecurity/tracee/types/api/v1beta1"
)

type Server struct {
	listener   net.Listener
	protocol   string
	listenAddr string
}

func New(protocol, listenAddr string) (*Server, error) {
	if protocol == "tcp" {
		listenAddr = ":" + listenAddr
	}

	lis, err := net.Listen(protocol, listenAddr)
	if err != nil {
		return nil, err
	}

	return &Server{listener: lis, protocol: protocol, listenAddr: listenAddr}, nil
}

func (s *Server) Start(ctx context.Context, tracee *ebpf.Tracee) {
	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()

	kk := keepalive.ServerParameters{
		// MaxConnectionIdle:     15 * time.Second, // If a client is idle for 15 seconds, send a GOAWAY
		// MaxConnectionAge: 30 * time.Second, // If any connection is alive for more than 30 seconds, send a GOAWAY
		// MaxConnectionAgeGrace: 5 * time.Second,  // Allow 5 seconds for pending RPCs to complete before forcibly closing connections
		Time:    5 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
		Timeout: 1 * time.Second, // Wait 1 second for the ping ack before assuming the connection is dead
	}

	// TODO: allow grpc keep alive configuration from CLI/Configfile
	grpcServer := grpc.NewServer(grpc.KeepaliveParams(kk))
	pb.RegisterTraceeServiceServer(grpcServer, &TraceeService{tracee: tracee})
	pb.RegisterDiagnosticServer(grpcServer, &DiagnosticService{tracee: tracee})

	go func() {
		logger.Debugw("Starting grpc server", "protocol", s.protocol, "address", s.listenAddr)
		if err := grpcServer.Serve(s.listener); err != nil {
			logger.Errorw("GRPC server", "error", err)
		}
		srvCancel()
	}()

	select {
	case <-ctx.Done():
		logger.Debugw("Context cancelled, shutting down grpc server")
		grpcServer.GracefulStop()
	// if server error occurred while base ctx is not done, we should exit via this case
	case <-srvCtx.Done():
	}
}
