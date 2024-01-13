package printer

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	forward "github.com/IBM/fluent-forward-go/fluent/client"
	"github.com/Masterminds/sprig/v3"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/types/trace"
)

type EventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(stats metrics.Stats)
	// Print prints a single event
	Print(event v1beta1.Event)
	// dispose of resources
	Close()
}

func New(cfg config.PrinterConfig) (EventPrinter, error) {
	var res EventPrinter
	kind := cfg.Kind

	if cfg.OutFile == nil {
		return res, errfmt.Errorf("out file is not set")
	}

	switch {
	case kind == "ignore":
		res = &ignoreEventPrinter{}
	case kind == "table":
		res = &tableEventPrinter{
			out:           cfg.OutFile,
			verbose:       false,
			containerMode: cfg.ContainerMode,
			relativeTS:    cfg.RelativeTS,
		}
	case kind == "table-verbose":
		res = &tableEventPrinter{
			out:           cfg.OutFile,
			verbose:       true,
			containerMode: cfg.ContainerMode,
			relativeTS:    cfg.RelativeTS,
		}
	case kind == "json":
		res = &jsonEventPrinter{
			out: cfg.OutFile,
		}
	case kind == "gob":
		res = &gobEventPrinter{
			out: cfg.OutFile,
		}
	case kind == "forward":
		res = &forwardEventPrinter{
			outPath: cfg.OutPath,
		}
	case kind == "webhook":
		res = &webhookEventPrinter{
			outPath: cfg.OutPath,
		}
	case strings.HasPrefix(kind, "gotemplate="):
		res = &templateEventPrinter{
			out:          cfg.OutFile,
			templatePath: strings.Split(kind, "=")[1],
		}
	}
	err := res.Init()
	if err != nil {
		return nil, err
	}
	return res, nil
}

type tableEventPrinter struct {
	out           io.WriteCloser
	verbose       bool
	containerMode config.ContainerMode
	relativeTS    bool
}

func (p tableEventPrinter) Init() error { return nil }

func (p tableEventPrinter) Preamble() {
	if p.verbose {
		switch p.containerMode {
		case config.ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-12s %-12s %-6s %-16s %-7s %-7s %-7s %-16s %-25s %s",
				"TIME",
				"UTS_NAME",
				"CONTAINER_ID",
				"MNT_NS",
				"PID_NS",
				"UID",
				"COMM",
				"PID",
				"TID",
				"PPID",
				"RET",
				"EVENT",
				"ARGS",
			)
		case config.ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-12s %-12s %-6s %-16s %-15s %-15s %-15s %-16s %-25s %s",
				"TIME",
				"UTS_NAME",
				"CONTAINER_ID",
				"MNT_NS",
				"PID_NS",
				"UID",
				"COMM",
				"PID/host",
				"TID/host",
				"PPID/host",
				"RET",
				"EVENT",
				"ARGS",
			)
		case config.ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-16s %-12s %-12s %-6s %-16s %-15s %-15s %-15s %-16s %-25s %s",
				"TIME",
				"UTS_NAME",
				"CONTAINER_ID",
				"IMAGE",
				"MNT_NS",
				"PID_NS",
				"UID",
				"COMM",
				"PID/host",
				"TID/host",
				"PPID/host",
				"RET",
				"EVENT",
				"ARGS",
			)
		}
	} else {
		switch p.containerMode {
		case config.ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-6s %-16s %-7s %-7s %-16s %-25s %s",
				"TIME",
				"UID",
				"COMM",
				"PID",
				"TID",
				"RET",
				"EVENT",
				"ARGS",
			)
		case config.ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-6s %-16s %-15s %-15s %-16s %-25s %s",
				"TIME",
				"CONTAINER_ID",
				"UID",
				"COMM",
				"PID/host",
				"TID/host",
				"RET",
				"EVENT",
				"ARGS",
			)
		case config.ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-16s %-6s %-16s %-15s %-15s %-16s %-25s %s",
				"TIME",
				"CONTAINER_ID",
				"IMAGE",
				"UID",
				"COMM",
				"PID/host",
				"TID/host",
				"RET",
				"EVENT",
				"ARGS",
			)
		}
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(event v1beta1.Event) {
	// TODO time
	// ut := time.Unix(0, int64(event.Timestamp))
	ut := time.Now()
	if p.relativeTS {
		ut = ut.UTC()
	}
	timestamp := fmt.Sprintf("%02d:%02d:%02d:%06d", ut.Hour(), ut.Minute(), ut.Second(), ut.Nanosecond()/1000)

	var (
		containerId    string
		containerImage string
	)

	if event.Context != nil && event.Context.Container != nil {
		containerId = event.Context.Container.Id
		if len(containerId) > 12 {
			containerId = containerId[:12]
		}
		containerImage = event.Context.Container.Image.Name
		if len(containerImage) > 16 {
			containerImage = containerImage[:16]
		}
	}

	eventName := event.Name
	if len(eventName) > 25 {
		eventName = eventName[:22] + "..."
	}

	if p.verbose {
		switch p.containerMode {
		case config.ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-12d %-12d %-6d %-16s %-7d %-7d %-7d %-16d %-25s ",
				timestamp,
				"no-host-name", // event.HostName,
				containerId,
				"no-mount-ns", // event.MountNS,
				"no-pid-ns",   // event.PIDNaS,
				event.Context.Process.RealUser.Id,
				event.Context.Process.Thread.Name,
				event.Context.Process.Pid,
				event.Context.Process.Thread.Tid,
				event.Context.Process.Parent.Pid,
				getReturnValue(event),
				event.Name,
			)
		case config.ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-12d %-12d %-6d %-16s %-7d/%-7d %-7d/%-7d %-7d/%-7d %-16d %-25s ",
				timestamp,
				"no-host-name", // event.HostName,
				containerId,
				"no-mount-ns", // event.MountNS,
				"no-pid-ns",   // event.PIDNS,
				event.Context.Process.RealUser.Id,
				event.Context.Process.Thread.Name,
				event.Context.Process.NamespacedPid,
				event.Context.Process.Pid,
				event.Context.Process.Thread.NamespacedTid,
				event.Context.Process.Thread.Tid,
				event.Context.Process.Parent.NamespacedPid,
				event.Context.Process.Parent.Pid,
				getReturnValue(event),
				event.Name,
			)
		case config.ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-16s %-12d %-12d %-6d %-16s %-7d/%-7d %-7d/%-7d %-7d/%-7d %-16d %-25s ",
				timestamp,
				"no-hostname", //event.HostName,
				containerId,
				event.Context.Container.Image.Name,
				"no-mount-ns", //event.MountNS,
				"no-pid-ns",   //event.PIDNS,
				event.Context.Process.RealUser.Id,
				event.Context.Process.Thread.Name,
				event.Context.Process.NamespacedPid,
				event.Context.Process.Pid,
				event.Context.Process.Thread.NamespacedTid,
				event.Context.Process.Thread.Tid,
				event.Context.Process.Parent.NamespacedPid,
				event.Context.Process.Parent.Pid,
				getReturnValue(event),
				event.Name,
			)
		}
	} else {
		switch p.containerMode {
		case config.ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-6d %-16s %-7d %-7d %-16d %-25s ",
				timestamp,
				event.Context.Process.RealUser.Id.Value,
				event.Context.Process.Thread.Name,
				event.Context.Process.Pid.Value,
				event.Context.Process.Thread.Tid.Value,
				getReturnValue(event),
				eventName,
			)
		case config.ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-6d %-16s %-7d/%-7d %-7d/%-7d %-16d %-25s ",
				timestamp,
				containerId,
				event.Context.Process.RealUser.Id.Value,
				event.Context.Process.Thread.Name,
				event.Context.Process.NamespacedPid.Value,
				event.Context.Process.Pid.Value,
				event.Context.Process.Thread.NamespacedTid.Value,
				event.Context.Process.Thread.Tid.Value,
				getReturnValue(event),
				eventName,
			)
		case config.ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-16s %-6d %-16s %-7d/%-7d %-7d/%-7d %-16d %-25s ",
				timestamp,
				containerId,
				containerImage,
				event.Context.Process.RealUser.Id.Value,
				event.Context.Process.Thread.Name,
				event.Context.Process.NamespacedPid.Value,
				event.Context.Process.Pid.Value,
				event.Context.Process.Thread.NamespacedTid.Value,
				event.Context.Process.Thread.Tid.Value,
				getReturnValue(event),
				eventName,
			)
		}
	}

	i := 0
	for name, eventValue := range event.EventData {
		value := GetFromEventValueString(eventValue)
		// triggeredBy from pkg/ebpf/finding.go breaks the table output,
		// so we simplify it
		if name == "triggeredBy" {
			// value = fmt.Sprintf("%s", value.(map[string]interface{})["name"])
		}

		if i == 0 {
			fmt.Fprintf(p.out, "%s: %v", name, value)
		} else {
			fmt.Fprintf(p.out, ", %s: %v", name, value)
		}
		i++
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Epilogue(stats metrics.Stats) {
	fmt.Println()
	fmt.Fprintf(p.out, "End of events stream\n")
	fmt.Fprintf(p.out, "Stats: %+v\n", stats)
}

func (p tableEventPrinter) Close() {
}

type templateEventPrinter struct {
	out          io.WriteCloser
	templatePath string
	templateObj  **template.Template
}

func (p *templateEventPrinter) Init() error {
	tmplPath := p.templatePath
	if tmplPath == "" {
		return errfmt.Errorf("please specify a gotemplate for event-based output")
	}
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return errfmt.WrapError(err)
	}
	p.templateObj = &tmpl

	return nil
}

func (p templateEventPrinter) Preamble() {}

func (p templateEventPrinter) Print(event v1beta1.Event) {
	if p.templateObj != nil {
		err := (*p.templateObj).Execute(p.out, event)
		if err != nil {
			logger.Errorw("Error executing template", "error", err)
		}
	} else {
		fmt.Fprintf(p.out, "Template Obj is nil")
	}
}

func (p templateEventPrinter) Epilogue(stats metrics.Stats) {}

func (p templateEventPrinter) Close() {
}

type jsonEventPrinter struct {
	out io.WriteCloser
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(event v1beta1.Event) {
	eBytes, err := json.Marshal(event)
	if err != nil {
		logger.Errorw("Error marshaling event to json", "error", err)
	}
	fmt.Fprintln(p.out, string(eBytes))
}

func (p jsonEventPrinter) Epilogue(stats metrics.Stats) {}

func (p jsonEventPrinter) Close() {
}

// gobEventPrinter is printing events using golang's builtin Gob serializer
type gobEventPrinter struct {
	out    io.WriteCloser
	outEnc *gob.Encoder
}

func (p *gobEventPrinter) Init() error {
	p.outEnc = gob.NewEncoder(p.out)

	// Event Types

	gob.Register(trace.Event{})
	gob.Register(trace.SlimCred{})
	gob.Register(make(map[string]string))
	gob.Register(trace.PktMeta{})
	gob.Register([]trace.HookedSymbolData{})
	gob.Register(map[string]trace.HookedSymbolData{})
	gob.Register([]trace.DnsQueryData{})
	gob.Register([]trace.DnsResponseData{})

	// Network Protocol Event Types

	// IPv4
	gob.Register(trace.ProtoIPv4{})
	// IPv6
	gob.Register(trace.ProtoIPv6{})
	// TCP
	gob.Register(trace.ProtoTCP{})
	// UDP
	gob.Register(trace.ProtoUDP{})
	// ICMP
	gob.Register(trace.ProtoICMP{})
	// ICMPv6
	gob.Register(trace.ProtoICMPv6{})
	// DNS
	gob.Register(trace.ProtoDNS{})
	gob.Register(trace.ProtoDNSQuestion{})
	gob.Register(trace.ProtoDNSResourceRecord{})
	gob.Register(trace.ProtoDNSSOA{})
	gob.Register(trace.ProtoDNSSRV{})
	gob.Register(trace.ProtoDNSMX{})
	gob.Register(trace.ProtoDNSURI{})
	gob.Register(trace.ProtoDNSOPT{})
	// HTTP
	gob.Register(trace.ProtoHTTP{})
	gob.Register(trace.ProtoHTTPRequest{})
	gob.Register(trace.ProtoHTTPResponse{})

	return nil
}

func (p *gobEventPrinter) Preamble() {}

func (p *gobEventPrinter) Print(event v1beta1.Event) {
	err := p.outEnc.Encode(event)
	if err != nil {
		logger.Errorw("Error encoding event to gob", "error", err)
	}
}

func (p *gobEventPrinter) Epilogue(stats metrics.Stats) {}

func (p gobEventPrinter) Close() {
}

// ignoreEventPrinter ignores events
type ignoreEventPrinter struct{}

func (p *ignoreEventPrinter) Init() error {
	return nil
}

func (p *ignoreEventPrinter) Preamble() {}

func (p *ignoreEventPrinter) Print(event v1beta1.Event) {}

func (p *ignoreEventPrinter) Epilogue(stats metrics.Stats) {}

func (p ignoreEventPrinter) Close() {}

// forwardEventPrinter sends events over the Fluent Forward protocol to a receiver
type forwardEventPrinter struct {
	outPath string
	url     *url.URL
	client  *forward.Client
	// These parameters can be set up from the URL
	tag string `default:"tracee"`
}

func getParameterValue(parameters url.Values, key string, defaultValue string) string {
	param, found := parameters[key]
	// Ensure we have a non-empty parameter set for this key
	if found && param[0] != "" {
		return param[0]
	}
	// Otherwise use the default value
	return defaultValue
}

func (p *forwardEventPrinter) Init() error {
	// Now parse the optional parameters with defaults and some basic verification
	u, err := url.Parse(p.outPath)
	if err != nil {
		return fmt.Errorf("unable to parse URL %q: %w", p.url, err)
	}
	p.url = u

	parameters, _ := url.ParseQuery(p.url.RawQuery)

	// Check if we have a tag set or default it
	p.tag = getParameterValue(parameters, "tag", "tracee")

	// Do we want to enable requireAck?
	requireAckString := getParameterValue(parameters, "requireAck", "false")
	requireAck, err := strconv.ParseBool(requireAckString)
	if err != nil {
		return errfmt.Errorf("unable to convert requireAck value %q: %v", requireAckString, err)
	}

	// Timeout conversion from string
	timeoutValueString := getParameterValue(parameters, "connectionTimeout", "10s")
	connectionTimeout, err := time.ParseDuration(timeoutValueString)
	if err != nil {
		return errfmt.Errorf("unable to convert connectionTimeout value %q: %v", timeoutValueString, err)
	}

	// We should have both username and password or neither for basic auth
	username := p.url.User.Username()
	password, isPasswordSet := p.url.User.Password()
	if username != "" && !isPasswordSet {
		return errfmt.Errorf("missing basic auth configuration for Forward destination")
	}

	// Ensure we support tcp or udp protocols
	protocol := "tcp"
	if p.url.Scheme != "" {
		protocol = p.url.Scheme
	}
	if protocol != "tcp" && protocol != "udp" {
		return errfmt.Errorf("unsupported protocol for Forward destination: %s", protocol)
	}

	// Extract the host (and port)
	address := p.url.Host
	logger.Infow("Attempting to connect to Forward destination", "url", address, "tag", p.tag)

	// Create a TCP connection to the forward receiver
	p.client = forward.New(forward.ConnectionOptions{
		Factory: &forward.ConnFactory{
			Network: protocol,
			Address: address,
		},
		RequireAck:        requireAck,
		ConnectionTimeout: connectionTimeout,
		AuthInfo: forward.AuthInfo{
			Username: username,
			Password: password,
		},
	})

	err = p.client.Connect()
	if err != nil {
		// The destination may not be available but may appear later so do not return an error here and just connect later.
		logger.Errorw("Error connecting to Forward destination", "url", p.url.String(), "error", err)
	}
	return nil
}

func (p *forwardEventPrinter) Preamble() {}

func (p *forwardEventPrinter) Print(event v1beta1.Event) {
	if p.client == nil {
		logger.Errorw("Invalid Forward client")
		return
	}

	// The actual event is marshalled as JSON then sent with the other information (tag, etc.)
	eBytes, err := json.Marshal(event)
	if err != nil {
		logger.Errorw("Error marshaling event to json", "error", err)
	}

	record := map[string]interface{}{
		"event": string(eBytes),
	}

	err = p.client.SendMessage(p.tag, record)
	// Assuming all is well we continue but if the connection is dropped or some other error we retry
	if err != nil {
		logger.Errorw("Error writing to Forward destination", "destination", p.url.Host, "tag", p.tag, "error", err)
		// Try five times to reconnect and send before giving up
		// TODO: consider using go-kit for circuit break, retry, etc
		for attempts := 0; attempts < 5; attempts++ {
			// Attempt to reconnect (remote end may have dropped/restarted)
			err = p.client.Reconnect()
			if err == nil {
				// Re-attempt to send
				err = p.client.SendMessage(p.tag, record)
				if err == nil {
					break
				}
			}
		}
	}
}

func (p *forwardEventPrinter) Epilogue(stats metrics.Stats) {}

func (p forwardEventPrinter) Close() {
	if p.client != nil {
		logger.Infow("Disconnecting from Forward destination", "url", p.url.Host, "tag", p.tag)
		if err := p.client.Disconnect(); err != nil {
			logger.Errorw("Disconnecting from Forward destination", "error", err)
		}
	}
}

type webhookEventPrinter struct {
	outPath     string
	url         *url.URL
	timeout     time.Duration
	templateObj *template.Template
	contentType string
}

func (ws *webhookEventPrinter) Init() error {
	u, err := url.Parse(ws.outPath)
	if err != nil {
		return errfmt.Errorf("unable to parse URL %q: %v", ws.outPath, err)
	}
	ws.url = u

	parameters, _ := url.ParseQuery(ws.url.RawQuery)

	timeout := getParameterValue(parameters, "timeout", "10s")
	t, err := time.ParseDuration(timeout)
	if err != nil {
		return errfmt.Errorf("unable to convert timeout value %q: %v", timeout, err)
	}
	ws.timeout = t

	gotemplate := getParameterValue(parameters, "gotemplate", "")
	if gotemplate != "" {
		tmpl, err := template.New(filepath.Base(gotemplate)).
			Funcs(sprig.TxtFuncMap()).
			ParseFiles(gotemplate)

		if err != nil {
			return errfmt.WrapError(err)
		}
		ws.templateObj = tmpl
	}

	contentType := getParameterValue(parameters, "contentType", "application/json")
	ws.contentType = contentType

	return nil
}

func (ws *webhookEventPrinter) Preamble() {}

func (ws *webhookEventPrinter) Print(event v1beta1.Event) {
	var (
		payload []byte
		err     error
	)

	if ws.templateObj != nil {
		buf := bytes.Buffer{}
		if err := ws.templateObj.Execute(&buf, event); err != nil {
			logger.Errorw("error writing to the template", "error", err)
			return
		}
		payload = buf.Bytes()
	} else {
		payload, err = json.Marshal(event)
		if err != nil {
			logger.Errorw("Error marshalling event", "error", err)
			return
		}
	}

	client := http.Client{Timeout: ws.timeout}

	req, err := http.NewRequest(http.MethodPost, ws.url.String(), bytes.NewReader(payload))
	if err != nil {
		logger.Errorw("Error creating request", "error", err)
		return
	}

	req.Header.Set("Content-Type", ws.contentType)

	resp, err := client.Do(req)
	if err != nil {
		logger.Errorw("Error sending webhook", "error", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		logger.Errorw(fmt.Sprintf("Error sending webhook, http status: %d", resp.StatusCode))
	}

	_ = resp.Body.Close()
}

func (ws *webhookEventPrinter) Epilogue(stats metrics.Stats) {}

func (ws *webhookEventPrinter) Close() {
}

// TEMP

func getReturnValue(event v1beta1.Event) int64 {
	if v, ok := event.EventData["returnValue"]; ok {
		if r := v.GetInt64(); r != nil {
			return r.GetValue()
		}
	}

	// return error? acho que nao, mas preciso pensar o porque!
	return 0
}

func GetFromEventValueString(ev *v1beta1.EventValue) string {
	fmt.Printf("aqui1 %T\n", ev.Value)

	switch ev.Value.(type) {
	case *v1beta1.EventValue_Int32:
		return fmt.Sprintf("%d", ev.GetInt32())
	case *v1beta1.EventValue_Int64:
		return fmt.Sprintf("%d", ev.GetInt64())
	case *v1beta1.EventValue_UInt32:
		return fmt.Sprintf("%d", ev.GetUInt32())
	case *v1beta1.EventValue_UInt64:
		return fmt.Sprintf("%d", ev.GetUInt64())
	case *v1beta1.EventValue_Str:
		return ev.GetStr().GetValue()
	case *v1beta1.EventValue_Bytes:
		return fmt.Sprintf("%s", ev.GetBytes())
	case *v1beta1.EventValue_Bool:
		return fmt.Sprintf("%t", ev.GetBool())
	case *v1beta1.EventValue_StrArray:
		return ev.GetStrArray().String()
	case *v1beta1.EventValue_Int32Array:
		return ev.GetInt32Array().String()
	case *v1beta1.EventValue_UInt64Array:
		return ev.GetUInt64Array().String()
	case *v1beta1.EventValue_Sockaddr:
		return ev.GetSockaddr().String()
	case *v1beta1.EventValue_Cred:
		return ev.GetCred().String()
	case *v1beta1.EventValue_Timespec:
		return ev.GetTimespec().String()
	case *v1beta1.EventValue_Args:
		return ""
	case *v1beta1.EventValue_TriggeredBy:
		return ev.GetTriggeredBy().String()
	case *v1beta1.EventValue_HookedSyscalls:
		return ev.GetHookedSyscalls().String()
	case *v1beta1.EventValue_HookedSeqOps:
		return ev.GetHookedSeqOps().String()
	case *v1beta1.EventValue_Ipv4:
		return ev.GetIpv4().String()
	case *v1beta1.EventValue_Ipv6:
		return ev.GetIpv6().String()
	case *v1beta1.EventValue_Tcp:
		return ev.GetTcp().String()
	case *v1beta1.EventValue_Udp:
		return ev.GetUdp().String()
	case *v1beta1.EventValue_Icmp:
		return ev.GetIcmp().String()
	case *v1beta1.EventValue_Icmpv6:
		return ev.GetIcmpv6().String()
	case *v1beta1.EventValue_Dns:
		return ev.GetDns().String()
	case *v1beta1.EventValue_DnsQuestions:
		return ev.GetDnsQuestions().String()
	case *v1beta1.EventValue_DnsResponses:
		return ev.GetDnsResponses().String()
	case *v1beta1.EventValue_PacketMetadata:
		return ev.GetPacketMetadata().String()
	case *v1beta1.EventValue_Http:
		return ev.GetHttp().String()
	case *v1beta1.EventValue_HttpRequest:
		return ev.GetHttpRequest().String()
	case *v1beta1.EventValue_HttpResponse:
		return ev.GetHttpResponse().String()
	case *v1beta1.EventValue_Struct:
		return ev.GetStruct().String()
	}
	return ""
}
