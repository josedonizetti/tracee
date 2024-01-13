package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unsafe"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Max depth of each stack trace to track (MAX_STACK_DETPH in eBPF code)
const maxStackDepth int = 20

// Matches 'NO_SYSCALL' in eBPF code
const noSyscall int32 = -1

// handleEvents is the main pipeline of tracee. It receives events from the perf buffer
// and passes them through a series of stages, each stage is a goroutine that performs a
// specific task on the event. The pipeline is started in a separate goroutine.
func (t *Tracee) handleEvents(ctx context.Context, initialized chan<- struct{}) {
	logger.Debugw("Starting handleEvents goroutine")
	defer logger.Debugw("Stopped handleEvents goroutine")

	var errcList []<-chan error

	// Decode stage: events are read from the perf buffer and decoded into trace.Event type.

	eventsChan, errc := t.decodeEvents(ctx, t.eventsChannel)
	errcList = append(errcList, errc)

	// Cache stage: events go through a caching function.

	if t.config.Cache != nil {
		eventsChan, errc = t.queueEvents(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Sort stage: events go through a sorting function.

	if t.config.Output.EventsSorting {
		eventsChan, errc = t.eventsSorter.StartPipeline(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Process events stage: events go through a processing functions.

	eventsChan, errc = t.processEvents(ctx, eventsChan)
	errcList = append(errcList, errc)

	// Enrichment stage: container events are enriched with additional runtime data.

	if !t.config.NoContainersEnrich { // TODO: remove safe-guard soon.
		eventsChan, errc = t.enrichContainerEvents(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Derive events stage: events go through a derivation function.

	eventsChan, errc = t.deriveEvents(ctx, eventsChan)
	errcList = append(errcList, errc)

	// Engine events stage: events go through the signatures engine for detection.

	if t.config.EngineConfig.Enabled {
		eventsChan, errc = t.engineEvents(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Sink pipeline stage: events go through printers.

	errc = t.sinkEvents(ctx, eventsChan)
	errcList = append(errcList, errc)

	initialized <- struct{}{}

	// Pipeline started. Waiting for pipeline to complete

	if err := t.WaitForPipeline(errcList...); err != nil {
		logger.Errorw("Pipeline", "error", err)
	}
}

// Under some circumstances, tracee-rules might be slower to consume events than
// tracee-ebpf is capable of generating them. This requires tracee-ebpf to deal with this
// possible lag, but, at the same, perf-buffer consumption can't be left behind (or
// important events coming from the kernel might be loss, causing detection misses).
//
// There are 3 variables connected to this issue:
//
// 1) perf buffer could be increased to hold very big amount of memory pages: The problem
// with this approach is that the requested space, to perf-buffer, through libbpf, has to
// be contiguous and it is almost impossible to get very big contiguous allocations
// through mmap after a node is running for some time.
//
// 2) raising the events channel buffer to hold a very big amount of events: The problem
// with this approach is that the overhead of dealing with that amount of buffers, in a
// golang channel, causes event losses as well. It means this is not enough to relief the
// pressure from kernel events into perf-buffer.
//
// 3) create an internal, to tracee-ebpf, buffer based on the node size.

// queueEvents is the cache pipeline stage. For each received event, it goes through a
// caching function that will enqueue the event into a queue. The queue is then de-queued
// by a different goroutine that will send the event down the pipeline.
func (t *Tracee) queueEvents(ctx context.Context, in <-chan *trace.Event) (chan *trace.Event, chan error) {
	out := make(chan *trace.Event, 10000)
	errc := make(chan error, 1)
	done := make(chan struct{}, 1)

	// receive and cache events (release pressure in the pipeline)
	go func() {
		for {
			select {
			case <-ctx.Done():
				done <- struct{}{}
				return
			case event := <-in:
				if event != nil {
					t.config.Cache.Enqueue(event) // may block if queue is full
				}
			}
		}
	}()

	// de-cache and send events (free cache space)
	go func() {
		defer close(out)
		defer close(errc)

		for {
			select {
			case <-done:
				return
			default:
				event := t.config.Cache.Dequeue() // may block if queue is empty
				if event != nil {
					out <- event
				}
			}
		}
	}()

	return out, errc
}

// decodeEvents is the event decoding pipeline stage. For each received event, it goes
// through a decoding function that will decode the event from its raw format into a
// trace.Event type.
func (t *Tracee) decodeEvents(ctx context.Context, sourceChan chan []byte) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event, 10000)
	errc := make(chan error, 1)
	sysCompatTranslation := events.Core.IDs32ToIDs()
	go func() {
		defer close(out)
		defer close(errc)
		for dataRaw := range sourceChan {
			ebpfMsgDecoder := bufferdecoder.New(dataRaw)
			var eCtx bufferdecoder.EventContext
			if err := ebpfMsgDecoder.DecodeContext(&eCtx); err != nil {
				t.handleError(err)
				continue
			}
			var argnum uint8
			if err := ebpfMsgDecoder.DecodeUint8(&argnum); err != nil {
				t.handleError(err)
				continue
			}
			eventId := events.ID(eCtx.EventID)
			if !events.Core.IsDefined(eventId) {
				t.handleError(errfmt.Errorf("failed to get configuration of event %d", eventId))
				continue
			}
			eventDefinition := events.Core.GetDefinitionByID(eventId)
			args := make([]trace.Argument, len(eventDefinition.GetParams()))
			err := ebpfMsgDecoder.DecodeArguments(args, int(argnum), eventDefinition, eventId)
			if err != nil {
				t.handleError(err)
				continue
			}

			// Add stack trace if needed
			var stackAddresses []uint64
			if t.config.Output.StackAddresses {
				stackAddresses = t.getStackAddresses(eCtx.StackID)
			}

			containerInfo := t.containers.GetCgroupInfo(eCtx.CgroupID).Container
			containerData := trace.Container{
				ID:          containerInfo.ContainerId,
				ImageName:   containerInfo.Image,
				ImageDigest: containerInfo.ImageDigest,
				Name:        containerInfo.Name,
			}
			kubernetesData := trace.Kubernetes{
				PodName:      containerInfo.Pod.Name,
				PodNamespace: containerInfo.Pod.Namespace,
				PodUID:       containerInfo.Pod.UID,
			}

			flags := parseContextFlags(containerData.ID, eCtx.Flags)
			syscall := ""
			if eCtx.Syscall != noSyscall {
				var err error
				syscall, err = parseSyscallID(int(eCtx.Syscall), flags.IsCompat, sysCompatTranslation)
				if err != nil {
					logger.Debugw("Originated syscall parsing", "error", err)
				}
			}

			// get an event pointer from the pool
			evt := t.eventsPool.Get().(*trace.Event)

			// populate all the fields of the event used in this stage, and reset the rest

			evt.Timestamp = int(eCtx.Ts)
			evt.ThreadStartTime = int(eCtx.StartTime)
			evt.ProcessorID = int(eCtx.ProcessorId)
			evt.ProcessID = int(eCtx.Pid)
			evt.ThreadID = int(eCtx.Tid)
			evt.ParentProcessID = int(eCtx.Ppid)
			evt.HostProcessID = int(eCtx.HostPid)
			evt.HostThreadID = int(eCtx.HostTid)
			evt.HostParentProcessID = int(eCtx.HostPpid)
			evt.UserID = int(eCtx.Uid)
			evt.MountNS = int(eCtx.MntID)
			evt.PIDNS = int(eCtx.PidID)
			evt.ProcessName = string(bytes.TrimRight(eCtx.Comm[:], "\x00"))
			evt.HostName = string(bytes.TrimRight(eCtx.UtsName[:], "\x00"))
			evt.CgroupID = uint(eCtx.CgroupID)
			evt.ContainerID = containerData.ID
			evt.Container = containerData
			evt.Kubernetes = kubernetesData
			evt.EventID = int(eCtx.EventID)
			evt.EventName = eventDefinition.GetName()
			evt.MatchedPoliciesKernel = eCtx.MatchedPolicies
			evt.MatchedPoliciesUser = 0
			evt.MatchedPolicies = []string{}
			evt.ArgsNum = int(argnum)
			evt.ReturnValue = int(eCtx.Retval)
			evt.Args = args
			evt.StackAddresses = stackAddresses
			evt.ContextFlags = flags
			evt.Syscall = syscall
			evt.Metadata = nil
			evt.ThreadEntityId = utils.HashTaskID(eCtx.HostTid, eCtx.StartTime)
			evt.ProcessEntityId = utils.HashTaskID(eCtx.HostPid, eCtx.LeaderStartTime)
			evt.ParentEntityId = utils.HashTaskID(eCtx.HostPpid, eCtx.ParentStartTime)

			// If there aren't any policies that need filtering in userland, tracee **may** skip
			// this event, as long as there aren't any derivatives or signatures that depend on it.
			// Some base events (derivative and signatures) might not have set related policy bit,
			// thus the need to continue with those within the pipeline.
			if t.matchPolicies(evt) == 0 {
				_, hasDerivation := t.eventDerivations[eventId]
				_, hasSignature := t.eventSignatures[eventId]

				if !hasDerivation && !hasSignature {
					_ = t.stats.EventsFiltered.Increment()
					t.eventsPool.Put(evt)
					continue
				}
			}

			select {
			case out <- evt:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errc
}

// matchPolicies does the userland filtering (policy matching) for events. It iterates through all
// existing policies, that were set by the kernel in the event bitmap. Some of those policies might
// not match the event after userland filters are applied. In those cases, the policy bit is cleared
// (so the event is "filtered" for that policy). This may be called in different stages of the
// pipeline (decode, derive, engine).
func (t *Tracee) matchPolicies(event *trace.Event) uint64 {
	eventID := events.ID(event.EventID)
	bitmap := event.MatchedPoliciesKernel

	// Short circuit if there are no policies in userland that need filtering.
	if bitmap&t.config.Policies.FilterableInUserland() == 0 {
		event.MatchedPoliciesUser = bitmap // store untoched bitmap to be used in sink stage
		return bitmap
	}

	for p := range t.config.Policies.FilterableInUserlandMap() { // range through each userland filterable policy
		// Policy ID is the bit offset in the bitmap.
		bitOffset := uint(p.ID)

		if !utils.HasBit(bitmap, bitOffset) { // event does not match this policy
			continue
		}

		// The event might have this policy bit set, but the policy might not have this
		// event ID. This happens whenever the event submitted by the kernel is going to
		// derive an event that this policy is interested in. In this case, don't do
		// anything and let the derivation stage handle this event.
		_, ok := p.EventsToTrace[eventID]
		if !ok {
			continue
		}

		//
		// Do the userland filtering
		//

		// 1. event context filters
		if !p.ContextFilter.Filter(*event) {
			utils.ClearBit(&bitmap, bitOffset)
			continue
		}

		// 2. event return value filters
		if !p.RetFilter.Filter(eventID, int64(event.ReturnValue)) {
			utils.ClearBit(&bitmap, bitOffset)
			continue
		}

		// 3. event arguments filters
		if !p.ArgFilter.Filter(eventID, event.Args) {
			utils.ClearBit(&bitmap, bitOffset)
			continue
		}

		//
		// Do the userland filtering for filters with global ranges
		//

		if p.UIDFilter.Enabled() {
			//
			// An event with a matched policy for global min/max range might not match all
			// policies with UID and PID filters with different min/max ranges, e.g.:
			//
			//   policy 59: comm=who, pid>100 and pid<1257738
			//   policy 30: comm=who, pid>502000 and pid<505000
			//
			// For kernel filtering, the flags from the example would compute:
			//
			// pid_max = 1257738
			// pid_min = 100
			//
			// Userland filtering needs to refine the bitmap to match the policies: A
			// "who" command with pid 150 is a match ONLY for the policy 59 in this
			// example.
			//
			// Clear the policy bit if the event UID is not in THIS policy UID min/max range:
			if !p.UIDFilter.InMinMaxRange(uint32(event.UserID)) {
				utils.ClearBit(&bitmap, bitOffset)
				continue
			}
		}

		if p.PIDFilter.Enabled() {
			//
			// The same happens for the global PID min/max range. Clear the policy bit if
			// the event PID is not in THIS policy PID min/max range.
			//
			if !p.PIDFilter.InMinMaxRange(uint32(event.HostProcessID)) {
				utils.ClearBit(&bitmap, bitOffset)
				continue
			}
		}
	}

	event.MatchedPoliciesUser = bitmap // store filtered bitmap to be used in sink stage

	return bitmap
}

func parseContextFlags(containerId string, flags uint32) trace.ContextFlags {
	const (
		contStartFlag = 1 << iota
		IsCompatFlag
	)

	var cflags trace.ContextFlags
	// Handle the edge case where containerStarted flag remains true despite an empty
	// containerId. See #3251 for more details.
	cflags.ContainerStarted = (containerId != "") && (flags&contStartFlag) != 0
	cflags.IsCompat = (flags & IsCompatFlag) != 0

	return cflags
}

// parseSyscallID returns the syscall name from its ID, taking into account architecture
// and 32bit/64bit modes. It also returns an error if the syscall ID is not found in the
// events definition.
func parseSyscallID(syscallID int, isCompat bool, compatTranslationMap map[events.ID]events.ID) (string, error) {
	id := events.ID(syscallID)
	if !isCompat {
		if !events.Core.IsDefined(id) {
			return "", errfmt.Errorf("no syscall event with syscall id %d", syscallID)
		}
		return events.Core.GetDefinitionByID(id).GetName(), nil
	}
	if id, ok := compatTranslationMap[events.ID(syscallID)]; ok {
		// should never happen (map should be initialized from events definition)
		if !events.Core.IsDefined(id) {
			return "", errfmt.Errorf(
				"no syscall event with compat syscall id %d, translated to ID %d", syscallID, id,
			)
		}
		return events.Core.GetDefinitionByID(id).GetName(), nil
	}
	return "", errfmt.Errorf("no syscall event with compat syscall id %d", syscallID)
}

// processEvents is the event processing pipeline stage. For each received event, it goes
// through all event processors and check if there is any internal processing needed for
// that event type.  It also clears policy bits for out-of-order container related events
// (after the processing logic). This stage also starts some logic that will be used by
// the processing logic in subsequent events.
func (t *Tracee) processEvents(ctx context.Context, in <-chan *trace.Event) (
	<-chan *trace.Event, <-chan error,
) {
	out := make(chan *trace.Event, 10000)
	errc := make(chan error, 1)

	// Some "informational" events are started here (TODO: API server?)
	t.invokeInitEvents(out)

	go func() {
		defer close(out)
		defer close(errc)

		for event := range in { // For each received event...
			if event == nil {
				continue // might happen during initialization (ctrl+c seg faults)
			}

			// Go through event processors if needed
			errs := t.processEvent(event)
			if len(errs) > 0 {
				for _, err := range errs {
					t.handleError(err)
				}
				t.eventsPool.Put(event)
				continue
			}

			// Get a bitmap with all policies containing container filters
			policiesWithContainerFilter := t.config.Policies.ContainerFilterEnabled()

			// Filter out events that don't have a container ID from all the policies that
			// have container filters. This will guarantee that any of those policies
			// won't get matched by this event. This situation might happen if the events
			// from a recently created container appear BEFORE the initial cgroup_mkdir of
			// that container root directory.  This could be solved by sorting the events
			// by a monotonic timestamp, for example, but sorting might not always be
			// enabled, so, in those cases, ignore the event IF the event is not a
			// cgroup_mkdir or cgroup_rmdir.

			if policiesWithContainerFilter > 0 && event.Container.ID == "" {
				eventId := events.ID(event.EventID)

				// never skip cgroup_{mkdir,rmdir}: container_{create,remove} events need it
				if eventId == events.CgroupMkdir || eventId == events.CgroupRmdir {
					goto sendEvent
				}

				logger.Debugw("False container positive", "event.Timestamp", event.Timestamp,
					"eventId", eventId)

				// remove event from the policies with container filters
				utils.ClearBits(&event.MatchedPoliciesKernel, policiesWithContainerFilter)
				utils.ClearBits(&event.MatchedPoliciesUser, policiesWithContainerFilter)

				if event.MatchedPoliciesKernel == 0 {
					t.eventsPool.Put(event)
					continue
				}
			}

		sendEvent:
			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errc
}

// deriveEVents is the event derivation pipeline stage. For each received event, it runs
// the event derivation logic, described in the derivation table, and send the derived
// events down the pipeline.
func (t *Tracee) deriveEvents(ctx context.Context, in <-chan *trace.Event) (
	<-chan *trace.Event, <-chan error,
) {
	out := make(chan *trace.Event)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		for {
			select {
			case event := <-in:
				if event == nil {
					continue // might happen during initialization (ctrl+c seg faults)
				}

				// Get a copy of our event before sending it down the pipeline. This is
				// needed because later modification of the event (in particular of the
				// matched policies) can affect the derivation and later pipeline logic
				// acting on the derived event.

				eventCopy := *event
				out <- event

				// Note: event is being derived before any of its args are parsed.
				derivatives, errors := t.eventDerivations.DeriveEvent(eventCopy)

				for _, err := range errors {
					t.handleError(err)
				}

				for i := range derivatives {
					// Passing "derivative" variable here will make the ptr address always
					// be the same as the last item. This makes the printer to print 2 or
					// 3 times the last event, instead of printing all derived events
					// (when there are more than one).
					//
					// Nadav: Likely related to https://github.com/golang/go/issues/57969 (GOEXPERIMENT=loopvar).
					//        Let's keep an eye on that moving from experimental for these and similar cases in tracee.
					event := &derivatives[i]

					// Skip events that dont work with filtering due to missing types
					// being handled (https://github.com/aquasecurity/tracee/issues/2486)
					switch events.ID(derivatives[i].EventID) {
					case events.SymbolsLoaded:
					case events.SharedObjectLoaded:
					case events.PrintMemDump:
					default:
						// Derived events might need filtering as well
						if t.matchPolicies(event) == 0 {
							_ = t.stats.EventsFiltered.Increment()
							continue
						}
					}

					// Process derived events
					t.processEvent(event)
					out <- event
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, errc
}

// sinkEvents is the event sink pipeline stage. For each received event, it goes through a
// series of printers that will print the event to the desired output. It also handles the
// event pool, returning the event to the pool after it is processed.
func (t *Tracee) sinkEvents(ctx context.Context, in <-chan *trace.Event) <-chan error {
	errc := make(chan error, 1)

	go func() {
		defer close(errc)

		for event := range in {
			if event == nil {
				continue // might happen during initialization (ctrl+c seg faults)
			}

			// Is the event enabled for the policies or globally?
			if !t.policyManager.IsEnabled(event.MatchedPoliciesUser, events.ID(event.EventID)) {
				// TODO: create metrics from dropped events
				t.eventsPool.Put(event)
				continue
			}

			// Only emit events requested by the user and matched by at least one policy.
			id := events.ID(event.EventID)
			event.MatchedPoliciesUser &= t.eventsState[id].Emit
			if event.MatchedPoliciesUser == 0 {
				t.eventsPool.Put(event)
				continue
			}

			// Populate the event with the names of the matched policies.
			event.MatchedPolicies = t.config.Policies.MatchedNames(event.MatchedPoliciesUser)

			// Parse args here if the rule engine is not enabled (parsed there if it is).
			if !t.config.EngineConfig.Enabled {
				err := t.parseArguments(event)
				if err != nil {
					t.handleError(err)
				}
			}

			// Send the event to the streams.
			select {
			case <-ctx.Done():
				return
			default:
				// fmt.Println("event: %v", event)
				// TODO: let's first replace down stream from here
				eventPB, err := convertTraceeEventToProto(*event)
				if err != nil {
					log.Fatal(err)
				}

				t.streamsManager.Publish(ctx, eventPB)
				_ = t.stats.EventCount.Increment()
				t.eventsPool.Put(event)
			}
		}
	}()

	return errc
}

// getStackAddresses returns the stack addresses for a given StackID
func (t *Tracee) getStackAddresses(stackID uint32) []uint64 {
	stackAddresses := make([]uint64, maxStackDepth)
	stackFrameSize := (strconv.IntSize / 8)

	// Lookup the StackID in the map
	// The ID could have aged out of the Map, as it only holds a finite number of
	// Stack IDs in it's Map
	stackBytes, err := t.StackAddressesMap.GetValue(unsafe.Pointer(&stackID))
	if err != nil {
		logger.Debugw("failed to get StackAddress", "error", err)
		return stackAddresses[0:0]
	}

	stackCounter := 0
	for i := 0; i < len(stackBytes); i += stackFrameSize {
		stackAddresses[stackCounter] = 0
		stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
		if stackAddr == 0 {
			break
		}
		stackAddresses[stackCounter] = stackAddr
		stackCounter++
	}

	// Attempt to remove the ID from the map so we don't fill it up
	// But if this fails continue on
	_ = t.StackAddressesMap.DeleteKey(unsafe.Pointer(&stackID))

	return stackAddresses[0:stackCounter]
}

// WaitForPipeline waits for results from all error channels.
func (t *Tracee) WaitForPipeline(errs ...<-chan error) error {
	errc := MergeErrors(errs...)
	for err := range errc {
		t.handleError(err)
	}
	return nil
}

// MergeErrors merges multiple channels of errors (https://blog.golang.org/pipelines)
func MergeErrors(cs ...<-chan error) <-chan error {
	var wg sync.WaitGroup
	// We must ensure that the output channel has the capacity to hold as many errors as
	// there are error channels. This will ensure that it never blocks, even if
	// WaitForPipeline returns early.
	out := make(chan error, len(cs))

	output := func(c <-chan error) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func (t *Tracee) handleError(err error) {
	_ = t.stats.ErrorCount.Increment()
	logger.Errorw("Tracee encountered an error", "error", err)
}

// parseArguments parses the arguments of the event. It must happen before the signatures
// are evaluated. For the new experience (cmd/tracee), it needs to happen in the the
// "events_engine" stage of the pipeline. For the old experience (cmd/tracee-ebpf &&
// cmd/tracee-rules), it happens on the "sink" stage of the pipeline (close to the
// printers).
func (t *Tracee) parseArguments(e *trace.Event) error {
	if t.config.Output.ParseArguments {
		err := events.ParseArgs(e)
		if err != nil {
			return errfmt.WrapError(err)
		}

		if t.config.Output.ParseArgumentsFDs {
			return events.ParseArgsFDs(e, uint64(t.getOrigEvtTimestamp(e)), t.FDArgPathMap)
		}
	}

	return nil
}

/// TEMP

func convertTraceeEventToProto(e trace.Event) (*pb.Event, error) {
	process := getProcess(e)
	container := getContainer(e)
	k8s := getK8s(e)

	var eventContext *pb.Context
	if process != nil || container != nil || k8s != nil {
		eventContext = &pb.Context{
			Process:   process,
			Container: container,
			K8S:       k8s,
		}
	}

	eventData, err := getEventData(e)
	if err != nil {
		return nil, err
	}

	var threat *pb.Threat
	if e.Metadata != nil {
		threat = getThreat(e.Metadata.Description, e.Metadata.Properties)
	}

	event := &pb.Event{
		Id:   uint32(e.EventID),
		Name: e.EventName,
		Policies: &pb.Policies{
			Matched: e.MatchedPolicies,
		},
		Context:   eventContext,
		Threat:    threat,
		EventData: eventData,
	}

	if e.Timestamp != 0 {
		event.Timestamp = timestamppb.New(time.Unix(int64(e.Timestamp), 0))
	}

	return event, nil
}

func getProcess(e trace.Event) *pb.Process {
	var userStackTrace *pb.UserStackTrace

	if len(e.StackAddresses) > 0 {
		userStackTrace = &pb.UserStackTrace{
			Addresses: getStackAddress(e.StackAddresses),
		}
	}

	var threadStartTime *timestamp.Timestamp
	if e.ThreadStartTime != 0 {
		threadStartTime = timestamppb.New(time.Unix(int64(e.ThreadStartTime), 0))
	}

	var executable *pb.Executable
	if e.Executable.Path != "" {
		executable = &pb.Executable{Path: e.Executable.Path}
	}

	return &pb.Process{
		Executable:    executable,
		EntityId:      wrapperspb.UInt32(e.ProcessEntityId),
		Pid:           wrapperspb.UInt32(uint32(e.HostProcessID)),
		NamespacedPid: wrapperspb.UInt32(uint32(e.ProcessID)),
		RealUser: &pb.User{
			Id: wrapperspb.UInt32(uint32(e.UserID)),
		},
		Thread: &pb.Thread{
			Start:          threadStartTime,
			Name:           e.ProcessName,
			EntityId:       wrapperspb.UInt32(e.ThreadEntityId),
			Tid:            wrapperspb.UInt32(uint32(e.HostThreadID)),
			NamespacedTid:  wrapperspb.UInt32(uint32(e.ThreadID)),
			Syscall:        e.Syscall,
			Compat:         e.ContextFlags.ContainerStarted,
			UserStackTrace: userStackTrace,
		},
		Parent: &pb.Process{
			EntityId:      wrapperspb.UInt32(e.ParentEntityId),
			Pid:           wrapperspb.UInt32(uint32(e.HostParentProcessID)),
			NamespacedPid: wrapperspb.UInt32(uint32(e.ParentProcessID)),
		},
	}
}

func getContainer(e trace.Event) *pb.Container {
	if e.Container.ID == "" && e.Container.Name == "" {
		return nil
	}

	container := &pb.Container{
		Id:   e.Container.ID,
		Name: e.Container.Name,
	}

	if e.Container.ImageName != "" {
		var repoDigest []string
		if e.Container.ImageDigest != "" {
			repoDigest = []string{e.Container.ImageDigest}
		}

		container.Image = &pb.ContainerImage{
			Name:        e.Container.ImageName,
			RepoDigests: repoDigest,
		}
	}

	return container
}

func getK8s(e trace.Event) *pb.K8S {
	if e.Kubernetes.PodName == "" &&
		e.Kubernetes.PodUID == "" &&
		e.Kubernetes.PodNamespace == "" {
		return nil
	}

	return &pb.K8S{
		Namespace: &pb.K8SNamespace{
			Name: e.Kubernetes.PodNamespace,
		},
		Pod: &pb.Pod{
			Name: e.Kubernetes.PodName,
			Uid:  e.Kubernetes.PodUID,
		},
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

func getStackAddress(stackAddresses []uint64) []*pb.StackAddress {
	var out []*pb.StackAddress
	for _, addr := range stackAddresses {
		out = append(out, &pb.StackAddress{Address: addr})
	}

	return out
}

func getEventData(e trace.Event) (map[string]*pb.EventValue, error) {
	data := make(map[string]*pb.EventValue)

	// for syscaslls
	args := make([]*pb.EventValue, 0)

	for _, arg := range e.Args {
		if arg.ArgMeta.Name == "triggeredBy" {
			triggerEvent, err := getTriggerBy(arg)
			if err != nil {
				return nil, err
			}
			data["triggeredBy"] = &pb.EventValue{
				Value: &pb.EventValue_TriggeredBy{
					TriggeredBy: triggerEvent,
				},
			}

			continue
		}

		eventValue, err := getEventValue(arg)
		if err != nil {
			return nil, err
		}

		if events.Core.GetDefinitionByID(events.ID(e.EventID)).IsSyscall() {
			args = append(args, eventValue)
			continue
		}

		data[arg.ArgMeta.Name] = eventValue
	}

	if len(args) > 0 {
		data["args"] = &pb.EventValue{
			Value: &pb.EventValue_Args{
				Args: &pb.ArgsValue{
					Value: args,
				},
			},
		}

		data["returnValue"] = &pb.EventValue{
			Value: &pb.EventValue_Int64{
				Int64: wrapperspb.Int64(int64(e.ReturnValue)),
			},
		}
	}

	return data, nil
}

func getEventValue(arg trace.Argument) (*pb.EventValue, error) {
	if arg.Value == nil {
		return nil, nil
	}

	var eventValue *pb.EventValue

	eventValue, err := parseArgument(arg)
	if err != nil {
		return nil, errfmt.Errorf("can't convert event data: %s - %v - %T", arg.Name, arg.Value, arg.Value)
	}

	return eventValue, nil
}

// parseArgument converts tracee argument to protobuf EventValue
// based on the value type
func parseArgument(arg trace.Argument) (*pb.EventValue, error) {
	switch v := arg.Value.(type) {
	case int:
		return &pb.EventValue{
			Value: &pb.EventValue_Int64{
				Int64: wrapperspb.Int64(int64(v)),
			},
		}, nil
	case int32:
		return &pb.EventValue{
			Value: &pb.EventValue_Int32{
				Int32: wrapperspb.Int32(v),
			},
		}, nil
	case uint8:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt32{
				UInt32: wrapperspb.UInt32(uint32(v)),
			},
		}, nil
	case uint16:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt32{
				UInt32: wrapperspb.UInt32(uint32(v)),
			},
		}, nil
	case uint32:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt32{
				UInt32: wrapperspb.UInt32(v),
			},
		}, nil
	case int64:
		return &pb.EventValue{
			Value: &pb.EventValue_Int64{
				Int64: wrapperspb.Int64(v),
			},
		}, nil
	case uint64:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt64{
				UInt64: wrapperspb.UInt64(v),
			},
		}, nil
	case bool:
		return &pb.EventValue{
			Value: &pb.EventValue_Bool{
				Bool: wrapperspb.Bool(v),
			},
		}, nil
	case string:
		return &pb.EventValue{
			Value: &pb.EventValue_Str{
				Str: wrapperspb.String(v),
			},
		}, nil
	case []string:
		strArray := make([]*wrappers.StringValue, 0, len(v))

		for _, str := range v {
			strArray = append(strArray, &wrappers.StringValue{Value: str})
		}

		return &pb.EventValue{
			Value: &pb.EventValue_StrArray{
				StrArray: &pb.StringArrayValue{
					Value: strArray,
				},
			},
		}, nil
	case map[string]string:
		sockaddr, err := getSockaddr(v)
		if err != nil {
			return nil, err
		}
		return sockaddr, nil
	case []byte:
		return &pb.EventValue{
			Value: &pb.EventValue_Bytes{
				Bytes: &wrappers.BytesValue{
					Value: v,
				},
			},
		}, nil
	case [2]int32:
		intArray := make([]*wrappers.Int32Value, 0, len(v))

		for _, i := range v {
			intArray = append(intArray, &wrappers.Int32Value{Value: i})
		}

		return &pb.EventValue{
			Value: &pb.EventValue_Int32Array{
				Int32Array: &pb.Int32ArrayValue{
					Value: intArray,
				},
			},
		}, nil
	case trace.SlimCred:
		return &pb.EventValue{
			Value: &pb.EventValue_Cred{
				Cred: &pb.CredValue{
					Uid:            wrapperspb.UInt32(v.Uid),
					Gid:            wrapperspb.UInt32(v.Gid),
					Suid:           wrapperspb.UInt32(v.Suid),
					Sgid:           wrapperspb.UInt32(v.Sgid),
					Euid:           wrapperspb.UInt32(v.Euid),
					Egid:           wrapperspb.UInt32(v.Egid),
					Fsuid:          wrapperspb.UInt32(v.Fsuid),
					Fsgid:          wrapperspb.UInt32(v.Fsgid),
					UserNamespace:  wrapperspb.UInt32(v.UserNamespace),
					SecureBits:     wrapperspb.UInt32(v.SecureBits),
					CapInheritable: getCaps(v.CapInheritable),
					CapPermitted:   getCaps(v.CapPermitted),
					CapEffective:   getCaps(v.CapEffective),
					CapBounding:    getCaps(v.CapBounding),
					CapAmbient:     getCaps(v.CapAmbient),
				},
			}}, nil
	case []uint64:
		uintArray := make([]*wrappers.UInt64Value, 0, len(v))

		for _, i := range v {
			uintArray = append(uintArray, &wrappers.UInt64Value{Value: i})
		}

		return &pb.EventValue{
			Value: &pb.EventValue_UInt64Array{
				UInt64Array: &pb.UInt64ArrayValue{
					Value: uintArray,
				},
			},
		}, nil
	case float64:
		return &pb.EventValue{
			Value: &pb.EventValue_Timespec{
				Timespec: &pb.TimespecValue{
					Value: wrapperspb.Double(v),
				},
			},
		}, nil
	case uintptr:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt64{
				UInt64: wrapperspb.UInt64(uint64(v)),
			},
		}, nil
	case trace.ProtoIPv4:
		return convertHttpIpv4(&v)
	case *trace.ProtoIPv4:
		return convertHttpIpv4(v)
	case trace.ProtoIPv6:
		return convertIpv6(&v)
	case *trace.ProtoIPv6:
		return convertIpv6(v)
	case trace.ProtoTCP:
		return convertTcp(&v)
	case *trace.ProtoTCP:
		return convertTcp(v)
	case trace.ProtoUDP:
		return convertUdp(&v)
	case *trace.ProtoUDP:
		return convertUdp(v)
	case trace.ProtoICMP:
		return convertIcmp(&v)
	case *trace.ProtoICMP:
		return convertIcmp(v)
	case trace.ProtoICMPv6:
		return convertIcmpv6(&v)
	case *trace.ProtoICMPv6:
		return convertIcmpv6(v)
	case trace.ProtoDNS:
		return convertDns(&v)
	case *trace.ProtoDNS:
		return convertDns(v)
	case trace.PktMeta:
		return convertPktMeta(&v)
	case *trace.PktMeta:
		return convertPktMeta(v)
	case trace.ProtoHTTP:
		return converProtoHttp(&v)
	case *trace.ProtoHTTP:
		return converProtoHttp(v)
	case trace.ProtoHTTPRequest:
		return converProtoHttpRequest(&v)
	case *trace.ProtoHTTPRequest:
		return converProtoHttpRequest(v)
	case trace.ProtoHTTPResponse:
		return converProtoHTTPResponse(&v)
	case *trace.ProtoHTTPResponse:
		return converProtoHTTPResponse(v)
	case []trace.DnsQueryData:
		questions := make([]*pb.DnsQueryData, len(v))
		for i, q := range v {
			questions[i] = &pb.DnsQueryData{
				Query:      q.Query,
				QueryType:  q.QueryType,
				QueryClass: q.QueryClass,
			}
		}

		return &pb.EventValue{
			Value: &pb.EventValue_DnsQuestions{
				DnsQuestions: &pb.DnsQuestions{
					Questions: questions,
				},
			},
		}, nil
	case []trace.DnsResponseData:
		responses := make([]*pb.DnsResponseData, len(v))
		for i, r := range v {
			answer := make([]*pb.DnsAnswer, len(r.DnsAnswer))
			for j, a := range r.DnsAnswer {
				answer[j] = &pb.DnsAnswer{
					Type:   a.Type,
					Ttl:    a.Ttl,
					Answer: a.Answer,
				}
			}

			responses[i] = &pb.DnsResponseData{
				DnsQueryData: &pb.DnsQueryData{
					Query:      r.QueryData.Query,
					QueryType:  r.QueryData.QueryType,
					QueryClass: r.QueryData.QueryClass,
				},
				DnsAnswer: answer,
			}
		}

		return &pb.EventValue{
			Value: &pb.EventValue_DnsResponses{
				DnsResponses: &pb.DnsResponses{
					Responses: responses,
				},
			},
		}, nil
	case []trace.HookedSymbolData:
		syscalls := make([]*pb.HookedSymbolData, len(v))
		for i, s := range v {
			syscalls[i] = &pb.HookedSymbolData{
				SymbolName:  s.SymbolName,
				ModuleOwner: s.ModuleOwner,
			}
		}

		return &pb.EventValue{
			Value: &pb.EventValue_HookedSyscalls{
				HookedSyscalls: &pb.HookedSyscalls{
					Value: syscalls,
				},
			}}, nil
	case map[string]trace.HookedSymbolData:
		m := make(map[string]*pb.HookedSymbolData)

		for k, v := range v {
			m[k] = &pb.HookedSymbolData{
				SymbolName:  v.SymbolName,
				ModuleOwner: v.ModuleOwner,
			}
		}

		return &pb.EventValue{
			Value: &pb.EventValue_HookedSeqOps{
				HookedSeqOps: &pb.HookedSeqOps{
					Value: m,
				},
			},
		}, nil
	case net.IP: // dns events use net.IP on src/dst
		return &pb.EventValue{
			Value: &pb.EventValue_Str{
				Str: wrapperspb.String(v.String()),
			},
		}, nil
	}

	return convertToStruct(arg)
}

func getCaps(c uint64) []pb.Capability {
	if c == 0 {
		return nil
	}

	caps := make([]pb.Capability, 0)

	for i := uint64(0); i < 64; i++ {
		if (1<<i)&c != 0 {
			e := pb.Capability(i)
			caps = append(caps, e)
		}
	}

	return caps
}

func getSockaddr(v map[string]string) (*pb.EventValue, error) {
	var sockaddr *pb.SockAddrValue
	switch v["sa_family"] {
	case "AF_INET":
		sinport, err := strconv.ParseUint(v["sin_port"], 10, 32)
		if err != nil {
			return nil, err
		}

		sockaddr = &pb.SockAddrValue{
			SaFamily: pb.SaFamilyT_AF_INET,
			SinPort:  uint32(sinport),
			SinAddr:  v["sin_addr"],
		}
	case "AF_UNIX":
		sockaddr = &pb.SockAddrValue{
			SaFamily: pb.SaFamilyT_AF_UNIX,
			SunPath:  v["sun_path"],
		}
	case "AF_INET6":
		sinport, err := strconv.ParseUint(v["sin6_port"], 10, 32)
		if err != nil {
			return nil, err
		}

		sin6Flowinfo, err := strconv.ParseUint(v["sin6_flowinfo"], 10, 32)
		if err != nil {
			return nil, err
		}

		sin6Scopeid, err := strconv.ParseUint(v["sin6_scopeid"], 10, 32)
		if err != nil {
			return nil, err
		}

		sockaddr = &pb.SockAddrValue{
			SaFamily:     pb.SaFamilyT_AF_INET6,
			Sin6Port:     uint32(sinport),
			Sin6Flowinfo: uint32(sin6Flowinfo),
			Sin6Scopeid:  uint32(sin6Scopeid),
			Sin6Addr:     v["sin6_addr"],
		}
	}

	return &pb.EventValue{
		Value: &pb.EventValue_Sockaddr{
			Sockaddr: sockaddr,
		},
	}, nil
}

func getTriggerBy(triggeredByArg trace.Argument) (*pb.TriggeredBy, error) {
	var triggerEvent *pb.TriggeredBy

	m, ok := triggeredByArg.Value.(map[string]interface{})
	if !ok {
		return nil, errfmt.Errorf("error getting triggering event: %v", triggeredByArg.Value)
	}

	triggerEvent = &pb.TriggeredBy{}

	id, ok := m["id"].(int)
	if !ok {
		return nil, errfmt.Errorf("error getting id of triggering event: %v", m)
	}
	triggerEvent.Id = uint32(id)

	name, ok := m["name"].(string)
	if !ok {
		return nil, errfmt.Errorf("error getting name of triggering event: %v", m)
	}
	triggerEvent.Name = name

	triggerEventArgs, ok := m["args"].([]trace.Argument)
	if !ok {
		return nil, errfmt.Errorf("error getting args of triggering event: %v", m)
	}

	data := make(map[string]*pb.EventValue)

	// for syscaslls
	args := make([]*pb.EventValue, 0)

	for _, arg := range triggerEventArgs {
		eventValue, err := getEventValue(arg)
		if err != nil {
			return nil, err
		}

		if events.Core.GetDefinitionByID(events.ID(id)).IsSyscall() {
			args = append(args, eventValue)
			continue
		}

		data[arg.ArgMeta.Name] = eventValue
	}

	if len(args) > 0 {
		data["args"] = &pb.EventValue{
			Value: &pb.EventValue_Args{
				Args: &pb.ArgsValue{
					Value: args,
				},
			},
		}

		data["returnValue"] = &pb.EventValue{
			Value: &pb.EventValue_Int64{
				Int64: wrapperspb.Int64(int64(m["returnValue"].(int))),
			},
		}
	}

	triggerEvent.Data = data

	return triggerEvent, nil
}

func getDNSResourceRecord(source trace.ProtoDNSResourceRecord) *pb.DNSResourceRecord {
	opts := make([]*pb.DNSOPT, len(source.OPT))

	for i, o := range source.OPT {
		opts[i] = &pb.DNSOPT{
			Code: o.Code,
			Data: o.Data,
		}
	}

	return &pb.DNSResourceRecord{
		Name:  source.Name,
		Type:  source.Type,
		Class: source.Class,
		Ttl:   uint32(source.TTL),
		Ip:    source.IP,
		Ns:    source.NS,
		Cname: source.CNAME,
		Ptr:   source.PTR,
		Txts:  source.TXTs,
		Soa: &pb.DNSSOA{
			Mname:   source.SOA.MName,
			Rname:   source.SOA.RName,
			Serial:  source.SOA.Serial,
			Refresh: source.SOA.Refresh,
			Retry:   source.SOA.Retry,
			Expire:  source.SOA.Expire,
			Minimum: source.SOA.Minimum,
		},
		Srv: &pb.DNSSRV{
			Priority: uint32(source.SRV.Priority),
			Weight:   uint32(source.SRV.Weight),
			Port:     uint32(source.SRV.Port),
			Name:     source.SRV.Name,
		},
		Mx: &pb.DNSMX{
			Preference: uint32(source.MX.Preference),
			Name:       source.MX.Name,
		},
		Opt: []*pb.DNSOPT{},
		Uri: &pb.DNSURI{
			Priority: uint32(source.URI.Priority),
			Weight:   uint32(source.URI.Weight),
			Target:   source.URI.Target,
		},
		Txt: source.TXT,
	}
}

func getHeaders(source http.Header) map[string]*pb.HttpHeader {
	headers := make(map[string]*pb.HttpHeader)

	for k, v := range source {
		headers[k] = &pb.HttpHeader{
			Header: v,
		}
	}

	return headers
}

func converProtoHTTPResponse(v *trace.ProtoHTTPResponse) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_HttpResponse{
			HttpResponse: &pb.HTTPResponse{
				Status:        v.Status,
				StatusCode:    int32(v.StatusCode),
				Protocol:      v.Protocol,
				Headers:       getHeaders(v.Headers),
				ContentLength: v.ContentLength,
			},
		}}, nil
}

func converProtoHttpRequest(v *trace.ProtoHTTPRequest) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_HttpRequest{
			HttpRequest: &pb.HTTPRequest{
				Method:        v.Method,
				Protocol:      v.Protocol,
				Host:          v.Host,
				UriPath:       v.URIPath,
				Headers:       getHeaders(v.Headers),
				ContentLength: v.ContentLength,
			},
		}}, nil
}

func converProtoHttp(v *trace.ProtoHTTP) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Http{
			Http: &pb.HTTP{
				Direction:     v.Direction,
				Method:        v.Method,
				Protocol:      v.Protocol,
				Host:          v.Host,
				UriPath:       v.URIPath,
				Status:        v.Status,
				StatusCode:    int32(v.StatusCode),
				Headers:       getHeaders(v.Headers),
				ContentLength: v.ContentLength,
			},
		}}, nil
}

func convertHttpIpv4(v *trace.ProtoIPv4) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Ipv4{
			Ipv4: &pb.IPv4{
				Version:    uint32(v.Version),
				Ihl:        uint32(v.IHL),
				Tos:        uint32(v.TOS),
				Length:     uint32(v.Length),
				Id:         uint32(v.Id),
				Flags:      uint32(v.Flags),
				FragOffset: uint32(v.FragOffset),
				Ttl:        uint32(v.TTL),
				Protocol:   v.Protocol,
				Checksum:   uint32(v.Checksum),
				SrcIp:      v.SrcIP,
				DstIp:      v.DstIP,
			},
		}}, nil
}

func convertIpv6(v *trace.ProtoIPv6) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Ipv6{
			Ipv6: &pb.IPv6{
				Version:      uint32(v.Version),
				TrafficClass: uint32(v.TrafficClass),
				FlowLabel:    v.FlowLabel,
				Length:       uint32(v.Length),
				NextHeader:   v.NextHeader,
				HopLimit:     uint32(v.HopLimit),
				SrcIp:        v.SrcIP,
				DstIp:        v.DstIP,
			},
		}}, nil
}

func convertTcp(v *trace.ProtoTCP) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Tcp{
			Tcp: &pb.TCP{
				SrcPort:    uint32(v.SrcPort),
				DstPort:    uint32(v.DstPort),
				Seq:        v.Seq,
				Ack:        v.Ack,
				DataOffset: uint32(v.DataOffset),
				FinFlag:    uint32(v.FIN),
				SynFlag:    uint32(v.SYN),
				RstFlag:    uint32(v.RST),
				PshFlag:    uint32(v.PSH),
				AckFlag:    uint32(v.ACK),
				UrgFlag:    uint32(v.URG),
				EceFlag:    uint32(v.ECE),
				CwrFlag:    uint32(v.CWR),
				NsFlag:     uint32(v.NS),
				Window:     uint32(v.Window),
				Checksum:   uint32(v.Checksum),
				Urgent:     uint32(v.Urgent),
			},
		}}, nil
}

func convertUdp(v *trace.ProtoUDP) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Udp{
			Udp: &pb.UDP{
				SrcPort:  uint32(v.SrcPort),
				DstPort:  uint32(v.DstPort),
				Length:   uint32(v.Length),
				Checksum: uint32(v.Checksum),
			},
		}}, nil
}

func convertIcmp(v *trace.ProtoICMP) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Icmp{
			Icmp: &pb.ICMP{
				TypeCode: v.TypeCode,
				Checksum: uint32(v.Checksum),
				Id:       uint32(v.Id),
				Seq:      uint32(v.Seq),
			},
		}}, nil
}

func convertIcmpv6(v *trace.ProtoICMPv6) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Icmpv6{
			Icmpv6: &pb.ICMPv6{
				TypeCode: v.TypeCode,
				Checksum: uint32(v.Checksum),
			},
		}}, nil
}

func convertDns(v *trace.ProtoDNS) (*pb.EventValue, error) {
	questions := make([]*pb.DNSQuestion, len(v.Questions))
	for i, q := range v.Questions {
		questions[i] = &pb.DNSQuestion{
			Name:  q.Name,
			Type:  q.Type,
			Class: q.Class,
		}
	}

	answers := make([]*pb.DNSResourceRecord, len(v.Answers))
	for i, a := range v.Answers {
		answers[i] = getDNSResourceRecord(a)
	}

	authorities := make([]*pb.DNSResourceRecord, len(v.Authorities))
	for i, a := range v.Authorities {
		authorities[i] = getDNSResourceRecord(a)
	}

	additionals := make([]*pb.DNSResourceRecord, len(v.Additionals))
	for i, a := range v.Additionals {
		additionals[i] = getDNSResourceRecord(a)
	}

	return &pb.EventValue{
		Value: &pb.EventValue_Dns{
			Dns: &pb.DNS{
				Id:           uint32(v.ID),
				Qr:           uint32(v.QR),
				OpCode:       v.OpCode,
				Aa:           uint32(v.AA),
				Tc:           uint32(v.TC),
				Rd:           uint32(v.RD),
				Ra:           uint32(v.RA),
				Z:            uint32(v.Z),
				ResponseCode: v.ResponseCode,
				QdCount:      uint32(v.QDCount),
				AnCount:      uint32(v.ANCount),
				NsCount:      uint32(v.NSCount),
				ArCount:      uint32(v.ARCount),
				Questions:    questions,
				Answers:      answers,
				Authorities:  authorities,
				Additionals:  additionals,
			},
		}}, nil
}

func convertPktMeta(v *trace.PktMeta) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_PacketMetadata{
			PacketMetadata: &pb.PktMeta{
				SrcIp:     v.SrcIP,
				DstIp:     v.DstIP,
				SrcPort:   uint32(v.SrcPort),
				DstPort:   uint32(v.DstPort),
				Protocol:  uint32(v.Protocol),
				PacketLen: v.PacketLen,
				Iface:     v.Iface,
			},
		}}, nil
}

func convertToStruct(arg trace.Argument) (*pb.EventValue, error) {
	i, ok := arg.Value.(detect.FindingDataStruct)
	if !ok {
		logger.Errorw(
			"Can't convert event argument. Please add it as a GRPC event data type or implement detect.FindingDataStruct interface.",
			"name",
			arg.Name,
			"type",
			fmt.Sprintf("%T", arg.Value),
		)

		return nil, nil
	}

	if m := i.ToMap(); m != nil {
		structValue, err := structpb.NewStruct(m)

		if err != nil {
			return nil, err
		}

		return &pb.EventValue{
			Value: &pb.EventValue_Struct{
				Struct: structValue,
			},
		}, nil
	}

	return nil, nil
}
