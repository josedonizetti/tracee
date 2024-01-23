package helpers

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/types"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

// IsFileWrite returns whether the passed file permissions string contains
// o_wronly or o_rdwr
func IsFileWrite(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_wronly") || strings.Contains(flagsLow, "o_rdwr") {
		return true
	}
	return false
}

// IsFileRead returns whether the passed file permissions string contains
// o_rdonly or o_rdwr
func IsFileRead(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_rdonly") || strings.Contains(flagsLow, "o_rdwr") {
		return true
	}
	return false
}

// IsMemoryPath checks if a given file path is located under "memfd", "/run/shm/" or "/dev/shm/".
func IsMemoryPath(pathname string) bool {
	if strings.HasPrefix(pathname, "memfd:") || strings.HasPrefix(pathname, "/run/shm/") ||
		strings.HasPrefix(pathname, "/dev/shm/") {
		return true
	}

	return false
}

// IsElf checks if the file starts with an ELF magic.
func IsElf(bytesArray []byte) bool {
	if len(bytesArray) >= 4 {
		if bytesArray[0] == 127 && bytesArray[1] == 69 && bytesArray[2] == 76 && bytesArray[3] == 70 {
			return true
		}
	}

	return false
}

func GetFamilyFromRawAddr(addr map[string]string) (string, error) {
	family, exists := addr["sa_family"]
	if !exists {
		return "", fmt.Errorf("family not found in address")
	}

	return family, nil
}

func IsInternetFamily(addr map[string]string) (bool, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return false, err
	}

	if family == "AF_INET" || family == "AF_INET6" {
		return true, nil
	}

	return false, nil
}

func IsUnixFamily(addr map[string]string) (bool, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return false, err
	}

	if family == "AF_UNIX" {
		return true, nil
	}

	return false, nil
}

func GetIPFromRawAddr(addr map[string]string) (string, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	ip := ""
	var exists bool

	switch family {
	case "AF_INET":
		ip, exists = addr["sin_addr"]
		if !exists {
			return "", fmt.Errorf("ip not found in address")
		}
	case "AF_INET6":
		ip, exists = addr["sin6_addr"]
		if !exists {
			return "", fmt.Errorf("ip not found in address")
		}
	default:
		return "", fmt.Errorf("address family not supported")
	}

	return ip, nil
}

func GetPortFromRawAddr(addr map[string]string) (string, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	port := ""
	var exists bool

	switch family {
	case "AF_INET":
		port, exists = addr["sin_port"]
		if !exists {
			return "", fmt.Errorf("port not found in address")
		}
	case "AF_INET6":
		port, exists = addr["sin6_port"]
		if !exists {
			return "", fmt.Errorf("port not found in address")
		}
	default:
		return "", fmt.Errorf("address family not supported")
	}

	return port, nil
}

func GetPathFromRawAddr(addr map[string]string) (string, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	path := ""
	var exists bool

	switch family {
	case "AF_UNIX":
		path, exists = addr["sun_path"]
		if !exists {
			return "", fmt.Errorf("path not found in address")
		}
	default:
		return "", fmt.Errorf("address family not supported")
	}

	return path, nil
}

//
// Network Protocol Event Types
//

// TODO: needs fixing
// GetPacketMetadata converts json to PacketMetadata
// func GetPacketMetadata(
// 	event types.Event,
// 	argName string) (
// 	trace.PacketMetadata, // TODO: need fixing
// 	error) {
// 	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
// 	if err != nil {
// 		return trace.PacketMetadata{}, err
// 	}

// 	argPacketMetadata, ok := arg.Value.(trace.PacketMetadata)
// 	if ok {
// 		return argPacketMetadata, nil
// 	}

// 	return trace.PacketMetadata{}, fmt.Errorf("packet metadata: type error (should be trace.PacketMetadata, is %T)", arg.Value)
// }

// GetProtoIPv4ByName converts json to ProtoIPv4
func GetProtoIPv4ByName(event *types.Event, argName string) (*pb.IPv4, error) {
	//
	// Current ProtoIPv4 type considered:
	//
	// type ProtoIPv4 struct {
	// 	Version    uint8             `json:"version"`
	// 	IHL        uint8             `json:"IHL"`
	// 	TOS        uint8             `json:"TOS"`
	// 	Length     uint16            `json:"length"`
	// 	Id         uint16            `json:"id"`
	// 	Flags      uint8             `json:"flags"`
	// 	FragOffset uint16            `json:"fragOffset"`
	// 	TTL        uint8             `json:"TTL"`
	// 	Protocol   string            `json:"protocol"`
	// 	Checksum   uint16            `json:"checksum"`
	// 	SrcIP      net.IP            `json:"srcIP"`
	// 	DstIP      net.IP            `json:"dstIP"`
	// }
	//

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}

	argProtoIPv4, ok := arg.Value.(*pb.EventValue_Ipv4)
	if ok {
		return argProtoIPv4.Ipv4, nil
	}

	return nil, fmt.Errorf("protocol IPv4: type error (should be trace.ProtoIPv4, is %T)", arg.Value)
}

// GetProtoIPv6ByName converts json to ProtoIPv6
func GetProtoIPv6ByName(event *types.Event, argName string) (*pb.IPv6, error) {
	//
	// Current ProtoIPv6 type considered:
	//
	// type ProtoIPv6 struct {
	// 	Version      uint8  `json:"version"`
	// 	TrafficClass uint8  `json:"trafficClass"`
	// 	FlowLabel    uint32 `json:"flowLabel"`
	// 	Length       uint16 `json:"length"`
	// 	NextHeader   string `json:"nextHeader"`
	// 	HopLimit     uint8  `json:"hopLimit"`
	// 	SrcIP        string `json:"srcIP"`
	// 	DstIP        string `json:"dstIP"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}

	argProtoIPv6, ok := arg.Value.(*pb.EventValue_Ipv6)
	if ok {
		return argProtoIPv6.Ipv6, nil
	}

	return nil, fmt.Errorf("protocol IPv6: type error (should be trace.ProtoIPv6, is %T)", arg.Value)
}

// GetProtoUDPByName converts json to ProtoUDP
func GetProtoUDPByName(event *types.Event, argName string) (*pb.UDP, error) {
	//
	// Current ProtoUDP type considered:
	//
	// type ProtoUDP struct {
	// 	SrcPort  uint16 `json:"srcPort"`
	// 	DstPort  uint16 `json:"dstPort"`
	// 	Length   uint16 `json:"length"`
	// 	Checksum uint16 `json:"checksum"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}

	argProtoUDP, ok := arg.Value.(*pb.EventValue_Udp)
	if ok {
		return argProtoUDP.Udp, nil
	}

	return nil, fmt.Errorf("protocol UDP: type error (should be trace.ProtoUDP, is %T)", arg.Value)
}

// GetProtoTCPByName converts json to ProtoTCP
func GetProtoTCPByName(event *types.Event, argName string) (*pb.TCP, error) {
	//
	// Current ProtoTCP type considered:
	//
	// type ProtoTCP struct {
	// SrcPort    uint16 `json:"srcPort"`
	// DstPort    uint16 `json:"dstPort"`
	// Seq        uint32 `json:"seq"`
	// Ack        uint32 `json:"ack"`
	// DataOffset uint8  `json:"dataOffset"`
	// FIN        uint8  `json:"FIN"`
	// SYN        uint8  `json:"SYN"`
	// RST        uint8  `json:"RST"`
	// PSH        uint8  `json:"PSH"`
	// ACK        uint8  `json:"ACK"`
	// URG        uint8  `json:"URG"`
	// ECE        uint8  `json:"ECE"`
	// CWR        uint8  `json:"CWR"`
	// NS         uint8  `json:"NS"`
	// Window     uint16 `json:"window"`
	// Checksum   uint16 `json:"checksum"`
	// Urgent     uint16 `json:"urgent"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}

	argProtoTCP, ok := arg.Value.(*pb.EventValue_Tcp)
	if ok {
		return argProtoTCP.Tcp, nil
	}

	return nil, fmt.Errorf("protocol TCP: type error (should be trace.ProtoTCP, is %T)", arg.Value)
}

// GetProtoICMPByName converts json to ProtoICMP
func GetProtoICMPByName(event *types.Event, argName string) (*pb.ICMP, error) {
	//
	// Current ProtoICMP type considered:
	//
	// type ProtoICMP struct {
	// 	TypeCode string `json:"typeCode"`
	// 	Checksum uint16 `json:"checksum"`
	// 	Id       uint16 `json:"id"`
	// 	Seq      uint16 `json:"seq"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}

	argProtoICMP, ok := arg.Value.(*pb.EventValue_Icmp)
	if ok {
		return argProtoICMP.Icmp, nil
	}

	return nil, fmt.Errorf("protocol ICMP: type error (should be trace.ProtoICMP, is %T)", arg.Value)
}

// GetProtoICMPv6ByName converts json to ProtoICMPv6
func GetProtoICMPv6ByName(event *types.Event, argName string) (*pb.ICMPv6, error) {
	//
	// Current ProtoICMPv6 type considered:
	//
	// type ProtoICMPv6 struct {
	// 	TypeCode string `json:"typeCode"`
	// 	Checksum uint16 `json:"checksum"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}

	argProtoICMPv6, ok := arg.Value.(*pb.EventValue_Icmpv6)
	if ok {
		return argProtoICMPv6.Icmpv6, nil
	}

	return nil, fmt.Errorf("protocol ICMPv6: type error (should be trace.ProtoICMPv6, is %T)", arg.Value)
}

// GetProtoDNSByName converts json to ProtoDNS
func GetProtoDNSByName(event *types.Event, argName string) (*pb.DNS, error) {
	//
	// Current ProtoDNS type considered:
	//
	// type ProtoDNS struct {
	// 	ID           uint16                   `json:"ID"`
	// 	QR           uint8                    `json:"QR"`
	// 	OpCode       string                   `json:"opCode"`
	// 	AA           uint8                    `json:"AA"`
	// 	TC           uint8                    `json:"TC"`
	// 	RD           uint8                    `json:"RD"`
	// 	RA           uint8                    `json:"RA"`
	// 	Z            uint8                    `json:"Z"`
	// 	ResponseCode string                   `json:"responseCode"`
	// 	QDCount      uint16                   `json:"QDCount"`
	// 	ANCount      uint16                   `json:"ANCount"`
	// 	NSCount      uint16                   `json:"NSCount"`
	// 	ARCount      uint16                   `json:"ARCount"`
	// 	Questions    []ProtoDNSQuestion       `json:"questions"`
	// 	Answers      []ProtoDNSResourceRecord `json:"answers"`
	// 	Authorities  []ProtoDNSResourceRecord `json:"authorities"`
	// 	Additionals  []ProtoDNSResourceRecord `json:"additionals"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}

	argProtoDNS, ok := arg.Value.(*pb.EventValue_Dns)
	if ok {
		return argProtoDNS.Dns, nil
	}

	return nil, fmt.Errorf("protocol DNS: type error (should be trace.ProtoDNS, is %T)", arg.Value)
}

func GetProtoHTTPByName(event *types.Event, argName string) (*pb.HTTP, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}

	argProtoHTTP, ok := arg.Value.(*pb.EventValue_Http)
	if ok {
		return argProtoHTTP.Http, nil
	}

	return nil, fmt.Errorf("protocol HTTP: type error (should be trace.ProtoHTTP, is %T)", arg.Value)
}
