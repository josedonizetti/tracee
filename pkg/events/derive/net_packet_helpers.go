package derive

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/types"
	"github.com/aquasecurity/tracee/types/trace"
)

// Event return value (retval) encodes network event information, such as:
//
// 0. L3 protocol (IPv4/IPv6)
// 1. packet flow direction (ingress/egress)
// 2. HTTP request/response direction
// 3. TCP Flow begin/end

const (
	familyIPv4 int = 1 << iota
	familyIPv6
	protoHTTPRequest
	protoHTTPResponse
	packetIngress
	packetEgress
	flowTCPBegin
	flowTCPEnd
	flowUDPBegin
	flowUDPEnd
	flowSrcInitiator
)

const httpMinLen int = 7 // longest http command is "DELETE "

type netPair struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	proto   uint8
	length  uint32
}

const (
	IPPROTO_TCP uint8 = 6
	IPPROTO_UDP uint8 = 17
)

//
// Helpers
//

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// convertArrayOfBytes converts a [][]byte to a []string.
func convertArrayOfBytes(given [][]byte) []string {
	res := make([]string, 0, len(given))

	for _, i := range given {
		res = append(res, string(i))
	}

	return res
}

func strToLower(given string) string {
	return strings.ToLower(given)
}

// parsePayloadArg returns the packet payload from the event.
func parsePayloadArg(event *types.Event) ([]byte, error) {
	var payloadArg *pb.EventValue
	for _, ev := range event.GetData() {
		if ev.Name == "payload" {
			payloadArg = ev
		}
	}

	if payloadArg == nil {
		return nil, noPayloadError()
	}
	payload, ok := payloadArg.Value.(*pb.EventValue_Bytes)
	if !ok {
		return nil, nonByteArgError()
	}
	payloadSize := len(payload.Bytes)
	if payloadSize < 1 {
		return nil, emptyPayloadError()
	}
	return payload.Bytes, nil
}

// getNetPair returns the network pair from the event.
// TODO: convert to trace.packetMetadata{}
func getPktMeta(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8, length uint32) *pb.PktMeta {
	return &pb.PktMeta{
		SrcIp:     srcIP.String(),
		DstIp:     dstIP.String(),
		SrcPort:   uint32(srcPort),
		DstPort:   uint32(dstPort),
		Protocol:  uint32(proto),
		PacketLen: length,
		Iface:     "any", // TODO: pick iface index from the kernel ?
	}
}

// swapSrcDst swaps the source and destination IP addresses and ports.
func swapSrcDst(s, d net.IP, sp, dp uint16) (net.IP, net.IP, uint16, uint16) {
	return d, s, dp, sp
}

// josedonizetti: fix me
// THIS is a tricy one, as we don't support on grpc
// getPacketDirection returns the packet direction from the event.
func getPacketDirection(event *types.Event) trace.PacketDirection {
	var returnValue int

	for _, ev := range event.GetData() {
		if ev.Name == "returnValue" {
			returnValue = int(ev.GetInt64())
			break
		}
	}

	switch {
	case returnValue&packetIngress == packetIngress:
		return trace.PacketIngress
	case returnValue&packetEgress == packetEgress:
		return trace.PacketEgress
	}
	return trace.InvalidPacketDirection
}

// getPacketHTTPDirection returns the packet HTTP direction from the event.
func getPacketHTTPDirection(event *types.Event) int {
	var returnValue int

	for _, ev := range event.GetData() {
		if ev.Name == "returnValue" {
			returnValue = int(ev.GetInt64())
			break
		}
	}

	switch {
	case returnValue&protoHTTPRequest == protoHTTPRequest:
		return protoHTTPRequest
	case returnValue&protoHTTPResponse == protoHTTPResponse:
		return protoHTTPResponse
	}
	return 0
}

// createPacketFromEvent creates a gopacket.Packet from the event.
func createPacketFromEvent(event *types.Event) (gopacket.Packet, error) {
	payload, err := parsePayloadArg(event)
	if err != nil {
		return nil, err
	}
	layer3TypeFlag, err := getLayer3TypeFlagFromEvent(event)
	if err != nil {
		return nil, err
	}
	layer3Type, err := getLayer3TypeFromFlag(layer3TypeFlag)
	if err != nil {
		return nil, err
	}

	packet := gopacket.NewPacket(
		payload,
		layer3Type,
		gopacket.Default,
	)
	if packet == nil {
		return nil, parsePacketError()
	}

	return packet, nil
}

// getDomainsFromCache returns the domain names of an IP address from the DNS cache.
func getDomainsFromCache(ip net.IP, cache *dnscache.DNSCache) []string {
	domains := []string{}
	if cache != nil {
		query, err := cache.Get(ip.String())
		if err != nil {
			switch err {
			case dnscache.ErrDNSRecordNotFound, dnscache.ErrDNSRecordExpired:
				domains = []string{}
			default:
				logger.Debugw("ip lookup error", "ip", ip, "error", err)
				return nil
			}
		} else {
			domains = query.DNSResults()
		}
	}
	return domains
}

//
// Layer 3 (Network Layer)
//

// getLayer3FromPacket returns the layer 3 protocol from the packet.
func getLayer3FromPacket(packet gopacket.Packet) (gopacket.NetworkLayer, error) {
	layer3 := packet.NetworkLayer()
	switch layer3.(type) {
	case (*layers.IPv4):
	case (*layers.IPv6):
	default:
		return nil, fmt.Errorf("wrong layer 3 protocol type")
	}
	return layer3, nil
}

// getLayer3IPv4FromPacket returns the IPv4 layer 3 from the packet.
func getLayer3IPv4FromPacket(packet gopacket.Packet) (*layers.IPv4, error) {
	layer3, err := getLayer3FromPacket(packet)
	if err != nil {
		return nil, err
	}
	ipv4, ok := layer3.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("wrong layer 3 protocol type")
	}
	return ipv4, nil
}

// getLayer3IPv6FromPacket returns the IPv6 layer 3 from the packet.
func getLayer3IPv6FromPacket(packet gopacket.Packet) (*layers.IPv6, error) {
	layer3, err := getLayer3FromPacket(packet)
	if err != nil {
		return nil, err
	}
	ipv6, ok := layer3.(*layers.IPv6)
	if !ok {
		return nil, fmt.Errorf("wrong layer 3 protocol type")
	}
	return ipv6, nil
}

// getSrcDstFromLayer3 returns the source and destination IP addresses from the layer 3.
func getSrcDstFromLayer3(layer3 gopacket.NetworkLayer) (net.IP, net.IP, error) {
	switch v := layer3.(type) {
	case (*layers.IPv4):
		return v.SrcIP, v.DstIP, nil
	case (*layers.IPv6):
		return v.SrcIP, v.DstIP, nil
	}
	return nil, nil, fmt.Errorf("wrong layer 3 protocol type")
}

// getLayer3SrcDstFromPacket returns the source and destination IP addresses from the packet.
func getLayer3SrcDstFromPacket(packet gopacket.Packet) (net.IP, net.IP, error) {
	layer3, err := getLayer3FromPacket(packet)
	if err != nil {
		return nil, nil, err
	}
	return getSrcDstFromLayer3(layer3)
}

// getLayer3TypeFromFlag returns the layer 3 protocol type from a given flag.
func getLayer3TypeFromFlag(layer3TypeFlag int) (gopacket.LayerType, error) {
	switch layer3TypeFlag {
	case familyIPv4:
		return layers.LayerTypeIPv4, nil
	case familyIPv6:
		return layers.LayerTypeIPv6, nil
	}
	return 0, fmt.Errorf("wrong layer 3 type")
}

// getLayer3TypeFlagFromEvent returns the layer 3 protocol type from a given event.
func getLayer3TypeFlagFromEvent(event *types.Event) (int, error) {

	var returnValue int
	for _, ev := range event.GetData() {
		if ev.Name == "returnValue" {
			returnValue = int(ev.GetInt64())
			break
		}
	}

	switch {
	case returnValue&familyIPv4 == familyIPv4:
		return familyIPv4, nil
	case returnValue&familyIPv6 == familyIPv6:
		return familyIPv6, nil
	}
	return 0, fmt.Errorf("wrong layer 3 ret value flag")
}

// getLengthFromPacket returns the packet length from a given packet.
func getLengthFromPacket(packet gopacket.Packet) (uint32, error) {
	layer3, err := getLayer3FromPacket(packet)
	if err != nil {
		return 0, err
	}
	switch v := layer3.(type) {
	case (*layers.IPv4):
		return uint32(v.Length), nil
	case (*layers.IPv6):
		return uint32(v.Length), nil
	}
	return 0, fmt.Errorf("wrong layer 3 protocol type")
}

//
// Layer 4 (Transport Layer)
//

// getLayer4FromPacket returns the layer 4 protocol from the packet.
func getLayer4FromPacket(packet gopacket.Packet) (gopacket.TransportLayer, error) {
	layer4 := packet.TransportLayer()
	switch layer4.(type) {
	case (*layers.TCP):
	case (*layers.UDP):
	default:
		return nil, fmt.Errorf("wrong layer 4 protocol type")
	}
	return layer4, nil
}

// getLayer4TCPFromPacket returns the TCP layer 4 from the packet.
func getLayer4TCPFromPacket(packet gopacket.Packet) (*layers.TCP, error) {
	layer4, err := getLayer4FromPacket(packet)
	if err != nil {
		return nil, err
	}
	tcp, ok := layer4.(*layers.TCP)
	if !ok {
		return nil, fmt.Errorf("wrong layer 4 protocol type")
	}
	return tcp, nil
}

// getLayer4UDPFromPacket returns the UDP layer 4 from the packet.
func getLayer4UDPFromPacket(packet gopacket.Packet) (*layers.UDP, error) {
	layer4, err := getLayer4FromPacket(packet)
	if err != nil {
		return nil, err
	}
	udp, ok := layer4.(*layers.UDP)
	if !ok {
		return nil, fmt.Errorf("wrong layer 4 protocol type")
	}
	return udp, nil
}

// getLayer4ProtoFromPacket returns the layer 4 protocol type from the packet.
func getLayer4ProtoFromPacket(packet gopacket.Packet) (uint8, error) {
	layer4, err := getLayer4FromPacket(packet)
	if err != nil {
		return 0, err
	}
	switch layer4.(type) {
	case (*layers.TCP):
		return IPPROTO_TCP, nil
	case (*layers.UDP):
		return IPPROTO_UDP, nil
	}
	return 0, fmt.Errorf("wrong layer 4 protocol type")
}

// getLayer4SrcPortDstPortFromPacket returns the source and destination ports from the packet.
func getLayer4SrcPortDstPortFromPacket(packet gopacket.Packet) (uint16, uint16, error) {
	layer4, err := getLayer4FromPacket(packet)
	if err != nil {
		return 0, 0, err
	}
	switch v := layer4.(type) {
	case (*layers.TCP):
		return uint16(v.SrcPort), uint16(v.DstPort), nil
	case (*layers.UDP):
		return uint16(v.SrcPort), uint16(v.DstPort), nil
	}
	return 0, 0, fmt.Errorf("wrong layer 4 protocol type")
}

//
// Special Layer (Some consider it as Layer 4, others Layer 3)
//

// getLayerICMPFromPacket returns the ICMP layer from the packet.
func getLayerICMPFromPacket(packet gopacket.Packet) (*layers.ICMPv4, error) {
	// ICMP might be considered Layer 3 (per OSI) or Layer 4 (per TCP/IP).
	layer := packet.Layer(layers.LayerTypeICMPv4)
	if layer == nil {
		return nil, fmt.Errorf("wrong layer protocol type")
	}
	icmp, ok := layer.(*layers.ICMPv4)
	if !ok {
		return nil, fmt.Errorf("wrong layer protocol type")
	}
	return icmp, nil
}

// getLayerICMPv6FromPacket returns the ICMPv6 layer from the packet.
func getLayerICMPv6FromPacket(packet gopacket.Packet) (*layers.ICMPv6, error) {
	// ICMP might be considered Layer 3 (per OSI) or Layer 4 (per TCP/IP).
	layer := packet.Layer(layers.LayerTypeICMPv6)
	if layer == nil {
		return nil, fmt.Errorf("wrong layer protocol type")
	}
	icmp, ok := layer.(*layers.ICMPv6)
	if !ok {
		return nil, fmt.Errorf("wrong layer protocol type")
	}
	return icmp, nil
}

//
// Layer 7 (Application Layer)
//

func getLayer7DNSFromPacket(packet gopacket.Packet) (*layers.DNS, error) {
	layer7, err := getLayer7FromPacket(packet)
	if err != nil {
		return nil, err
	}
	switch l7 := layer7.(type) {
	case (*layers.DNS):
		return l7, nil
	}
	return nil, fmt.Errorf("wrong layer 7 protocol type")
}

// getLayer7FromPacket returns the layer 7 protocol from the packet.
func getLayer7FromPacket(packet gopacket.Packet) (gopacket.ApplicationLayer, error) {
	layer7 := packet.ApplicationLayer()
	if layer7 == nil {
		return nil, fmt.Errorf("wrong layer 7 protocol type")
	}
	return layer7, nil
}

//
// Proto Types (tracee/types/trace)
//

// getProtoIPv4 returns the ProtoIPv4 from the IPv4.
func getProtoIPv4(ipv4 *layers.IPv4) *pb.IPv4 {
	// TODO: IPv4 options if IHL > 5
	return &pb.IPv4{
		Version:    uint32(ipv4.Version),
		Ihl:        uint32(ipv4.IHL),
		Tos:        uint32(ipv4.TOS),
		Length:     uint32(ipv4.Length),
		Id:         uint32(ipv4.Id),
		Flags:      uint32(ipv4.Flags),
		FragOffset: uint32(ipv4.FragOffset),
		Ttl:        uint32(ipv4.TTL),
		Protocol:   ipv4.Protocol.String(),
		Checksum:   uint32(ipv4.Checksum),
		SrcIp:      ipv4.SrcIP.String(),
		DstIp:      ipv4.DstIP.String(),
	}
}

// getProtoIPv6 returns the ProtoIPv6 from the IPv6.
func getProtoIPv6(ipv6 *layers.IPv6) *pb.IPv6 {
	return &pb.IPv6{
		Version:      uint32(ipv6.Version),
		TrafficClass: uint32(ipv6.TrafficClass),
		FlowLabel:    ipv6.FlowLabel,
		Length:       uint32(ipv6.Length),
		NextHeader:   ipv6.NextHeader.String(),
		HopLimit:     uint32(ipv6.HopLimit),
		SrcIp:        ipv6.SrcIP.String(),
		DstIp:        ipv6.DstIP.String(),
	}
}

// getProtoTCP returns the ProtoTCP from the TCP.
func getProtoTCP(tcp *layers.TCP) *pb.TCP {
	return &pb.TCP{
		SrcPort:    uint32(tcp.SrcPort),
		DstPort:    uint32(tcp.DstPort),
		Seq:        tcp.Seq,
		Ack:        tcp.Ack,
		DataOffset: uint32(tcp.DataOffset),
		FinFlag:    uint32(boolToUint8(tcp.FIN)),
		SynFlag:    uint32(boolToUint8(tcp.SYN)),
		RstFlag:    uint32(boolToUint8(tcp.RST)),
		PshFlag:    uint32(boolToUint8(tcp.PSH)),
		AckFlag:    uint32(boolToUint8(tcp.ACK)),
		UrgFlag:    uint32(boolToUint8(tcp.URG)),
		EceFlag:    uint32(boolToUint8(tcp.ECE)),
		NsFlag:     uint32(boolToUint8(tcp.NS)),
		Window:     uint32(tcp.Window),
		Checksum:   uint32(tcp.Checksum),
		Urgent:     uint32(tcp.Urgent),
		// TODO: TCP options
	}
}

// getProtoUDP returns the ProtoUDP from the UDP.
func getProtoUDP(udp *layers.UDP) *pb.UDP {
	return &pb.UDP{
		SrcPort:  uint32(udp.SrcPort),
		DstPort:  uint32(udp.DstPort),
		Length:   uint32(udp.Length),
		Checksum: uint32(udp.Checksum),
	}
}

// getProtoICMP returns the ProtoICMP from the ICMP.
func getProtoICMP(icmp *layers.ICMPv4) *pb.ICMP {
	return &pb.ICMP{
		TypeCode: icmp.TypeCode.String(),
		Checksum: uint32(icmp.Checksum),
		Id:       uint32(icmp.Id),
		Seq:      uint32(icmp.Seq),
	}
}

// getProtoICMPv6 returns the ProtoICMPv6 from the ICMPv6.
func getProtoICMPv6(icmpv6 *layers.ICMPv6) *pb.ICMPv6 {
	return &pb.ICMPv6{
		TypeCode: icmpv6.TypeCode.String(),
		Checksum: uint32(icmpv6.Checksum),
	}
}

// getProtoDNS returns the ProtoDNS from the DNS.
func getProtoDNS(dns *layers.DNS) *pb.DNS {
	proto := &pb.DNS{
		Id:           uint32(dns.ID),
		Qr:           uint32(boolToUint8(dns.QR)),
		OpCode:       strToLower(dns.OpCode.String()),
		Aa:           uint32(boolToUint8(dns.AA)),
		Tc:           uint32(boolToUint8(dns.TC)),
		Rd:           uint32(boolToUint8(dns.RD)),
		Ra:           uint32(boolToUint8(dns.RA)),
		Z:            uint32(dns.Z),
		ResponseCode: strToLower(dns.ResponseCode.String()),
		QdCount:      uint32(dns.QDCount),
		AnCount:      uint32(dns.ANCount),
		NsCount:      uint32(dns.NSCount),
		ArCount:      uint32(dns.ARCount),
	}

	// Process all existing questions (if any).
	proto.Questions = make([]*pb.DNSQuestion, 0, len(dns.Questions))
	proto.Answers = make([]*pb.DNSResourceRecord, 0, len(dns.Answers))
	proto.Authorities = make([]*pb.DNSResourceRecord, 0, len(dns.Authorities))
	proto.Additionals = make([]*pb.DNSResourceRecord, 0, len(dns.Additionals))

	for _, question := range dns.Questions {
		proto.Questions = append(proto.Questions, getProtoDNSQuestion(question))
	}

	for _, answer := range dns.Answers {
		proto.Answers = append(proto.Answers, getProtoDNSResourceRecord(answer))
	}

	for _, auth := range dns.Authorities {
		proto.Authorities = append(proto.Authorities, getProtoDNSResourceRecord(auth))
	}

	for _, add := range dns.Additionals {
		proto.Additionals = append(proto.Additionals, getProtoDNSResourceRecord(add))
	}

	return proto
}

// getProtoDNSQuestion returns the ProtoDNSQuestion from the DNSQuestion.
func getProtoDNSQuestion(question layers.DNSQuestion) *pb.DNSQuestion {
	return &pb.DNSQuestion{
		Name:  string(question.Name),
		Type:  question.Type.String(),
		Class: question.Class.String(),
	}
}

// getProtoDNSResourceRecord returns the ProtoDNSResourceRecord from the DNSResourceRecord.
func getProtoDNSResourceRecord(record layers.DNSResourceRecord) *pb.DNSResourceRecord {
	var ip string

	if record.IP != nil {
		ip = record.IP.String()
	}

	return &pb.DNSResourceRecord{
		Name:  string(record.Name),
		Type:  record.Type.String(),
		Class: record.Class.String(),
		Ttl:   record.TTL,
		Ip:    ip,
		Ns:    string(record.NS),
		Cname: string(record.CNAME),
		Ptr:   string(record.PTR),
		Txts:  convertArrayOfBytes(record.TXTs),
		Soa: &pb.DNSSOA{
			Mname:   string(record.SOA.MName),
			Rname:   string(record.SOA.RName),
			Serial:  record.SOA.Serial,
			Refresh: record.SOA.Refresh,
			Retry:   record.SOA.Retry,
			Expire:  record.SOA.Expire,
			Minimum: record.SOA.Minimum,
		},
		Srv: &pb.DNSSRV{
			Priority: uint32(record.SRV.Priority),
			Weight:   uint32(record.SRV.Weight),
			Port:     uint32(record.SRV.Port),
			Name:     string(record.SRV.Name),
		},
		Mx: &pb.DNSMX{
			Preference: uint32(record.MX.Preference),
			Name:       string(record.MX.Name),
		},
		Opt: getDNSOPT(record.OPT),
		Uri: &pb.DNSURI{
			Priority: uint32(record.URI.Priority),
			Weight:   uint32(record.URI.Weight),
			Target:   string(record.URI.Target),
		},
		Txt: string(record.TXT),
	}
}

// getDNSOPT returns the ProtoDNSOPT from the DNSOPT.
func getDNSOPT(opt []layers.DNSOPT) []*pb.DNSOPT {
	res := make([]*pb.DNSOPT, 0, len(opt))

	for _, j := range opt {
		res = append(res,
			&pb.DNSOPT{
				Code: j.Code.String(),
				Data: string(j.Data),
			},
		)
	}

	return res
}

// getProtoHTTPFromRequestPacket returns the ProtoHTTP from the HTTP request packet.
func getProtoHTTPFromRequestPacket(packet gopacket.Packet) (*pb.HTTP, error) {
	layer7, err := getLayer7FromPacket(packet)
	if err != nil {
		return nil, err
	}

	layer7Payload := layer7.Payload()

	if len(layer7Payload) < httpMinLen {
		return nil, nil // regular tcp/ip packet without HTTP payload
	}

	reader := bufio.NewReader(bytes.NewReader(layer7Payload))

	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}

	return &pb.HTTP{
		Direction:     "request",
		Method:        request.Method,
		Protocol:      request.Proto,
		Host:          request.Host,
		UriPath:       request.URL.Path,
		Headers:       getHeaders(request.Header),
		ContentLength: request.ContentLength,
	}, nil
}

// getProtoHTTPFromResponsePacket returns the ProtoHTTP from the HTTP response packet.
func getProtoHTTPFromResponsePacket(packet gopacket.Packet) (*pb.HTTP, error) {
	layer7, err := getLayer7FromPacket(packet)
	if err != nil {
		return nil, err
	}

	layer7Payload := layer7.Payload()

	if len(layer7Payload) < httpMinLen {
		return nil, nil // regular tcp/ip packet without HTTP payload
	}

	reader := bufio.NewReader(bytes.NewReader(layer7Payload))

	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, err
	}

	return &pb.HTTP{
		Direction:     "response",
		Status:        response.Status,
		StatusCode:    int32(response.StatusCode),
		Protocol:      response.Proto,
		Headers:       getHeaders(response.Header),
		ContentLength: response.ContentLength,
	}, nil
}

// getProtoHTTPRequestFromHTTP returns the ProtoHTTPRequest from the ProtoHTTP.
func getProtoHTTPRequestFromHTTP(proto *pb.HTTP) *pb.HTTPRequest {
	return &pb.HTTPRequest{
		Method:        proto.Method,
		Protocol:      proto.Protocol,
		Host:          proto.Host,
		UriPath:       proto.UriPath,
		Headers:       proto.Headers,
		ContentLength: proto.ContentLength,
	}
}

// getProtoHTTPResponseFromHTTP returns the ProtoHTTPResponse from the ProtoHTTP.
func getProtoHTTPResponseFromHTTP(proto *pb.HTTP) *pb.HTTPResponse {
	return &pb.HTTPResponse{
		Status:        proto.Status,
		StatusCode:    proto.StatusCode,
		Protocol:      proto.Protocol,
		Headers:       proto.Headers,
		ContentLength: proto.ContentLength,
	}
}

// getDNSQueryFromProtoDNS converts a NetPacketDNS to a DnsQueryData.
func getDNSQueryFromProtoDNS(questions []*pb.DNSQuestion) []*pb.DnsQueryData {
	requests := make([]*pb.DnsQueryData, 0, len(questions))

	for _, question := range questions {
		requests = append(requests,
			&pb.DnsQueryData{
				Query:      question.Name,
				QueryType:  question.Type,
				QueryClass: question.Class,
			},
		)
	}

	return requests
}

// getDNSResponseFromProtoDNS converts a NetPacketDNS to a DnsResponseData.
func getDNSResponseFromProtoDNS(query *pb.DnsQueryData, answers []*pb.DNSResourceRecord) []*pb.DnsResponseData {
	dnsAnswers := make([]*pb.DnsAnswer, 0, len(answers))

	for _, answer := range answers {
		dnsAnswer := &pb.DnsAnswer{}

		switch answer.Type {
		case "A":
			dnsAnswer.Answer = answer.Ip
		case "AAAA":
			dnsAnswer.Answer = answer.Ip
		case "NS":
			dnsAnswer.Answer = answer.Ns
		case "CNAME":
			dnsAnswer.Answer = answer.Cname
		case "PTR":
			dnsAnswer.Answer = answer.Ptr
		case "MX":
			dnsAnswer.Answer = answer.Mx.GetName()
		case "TXT":
			dnsAnswer.Answer = answer.Txt
		default:
			dnsAnswer.Answer = "not implemented"
		}

		dnsAnswer.Type = answer.Type
		dnsAnswer.Ttl = answer.Ttl

		dnsAnswers = append(dnsAnswers, dnsAnswer)
	}

	return []*pb.DnsResponseData{
		{
			DnsQueryData: query,
			DnsAnswer:    dnsAnswers,
		},
	}
}

// TODO this is a duplicate function, there is one like it in event_data.go
func getHeaders(source http.Header) map[string]*pb.HttpHeader {
	headers := make(map[string]*pb.HttpHeader)

	for k, v := range source {
		headers[k] = &pb.HttpHeader{
			Header: v,
		}
	}

	return headers
}
