package events

import (
	"bytes"
	"fmt"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/types"
	"github.com/aquasecurity/tracee/types/trace"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func ParseArgs(event *trace.Event) error {
	for i := range event.Args {
		if ptr, isUintptr := event.Args[i].Value.(uintptr); isUintptr {
			event.Args[i].Value = "0x" + strconv.FormatUint(uint64(ptr), 16)
		}
	}

	emptyString := func(arg *trace.Argument) {
		arg.Type = "string"
		arg.Value = ""
	}

	parseOrEmptyString := func(arg *trace.Argument, sysArg helpers.SystemFunctionArgument, err error) {
		emptyString(arg)
		if err == nil {
			arg.Value = sysArg.String()
		}
	}

	switch ID(event.EventID) {
	case MemProtAlert:
		if alertArg := GetArg(event, "alert"); alertArg != nil {
			if alert, isUint32 := alertArg.Value.(uint32); isUint32 {
				alertArg.Value = trace.MemProtAlert(alert).String()
				alertArg.Type = "string"
			}
		}
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
		if prevProtArg := GetArg(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prevProt))
				parseOrEmptyString(prevProtArg, mmapProtArgument, nil)
			}
		}
	case SysEnter, SysExit:
		if syscallArg := GetArg(event, "syscall"); syscallArg != nil {
			if id, isInt32 := syscallArg.Value.(int32); isInt32 {
				if Core.IsDefined(ID(id)) {
					eventDefinition := Core.GetDefinitionByID(ID(id))
					if eventDefinition.IsSyscall() {
						syscallArg.Value = eventDefinition.GetName()
						syscallArg.Type = "string"
					}
				}
			}
		}
	case CapCapable:
		if capArg := GetArg(event, "cap"); capArg != nil {
			if capability, isInt32 := capArg.Value.(int32); isInt32 {
				capabilityFlagArgument, err := helpers.ParseCapability(uint64(capability))
				parseOrEmptyString(capArg, capabilityFlagArgument, err)
			}
		}
	case SecurityMmapFile, DoMmap:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isUint64 := protArg.Value.(uint64); isUint64 {
				mmapProtArgument := helpers.ParseMmapProt(prot)
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case Mmap, Mprotect, PkeyMprotect:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case SecurityFileMprotect:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
		if prevProtArg := GetArg(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prevProt))
				parseOrEmptyString(prevProtArg, mmapProtArgument, nil)
			}
		}
	case Ptrace:
		if reqArg := GetArg(event, "request"); reqArg != nil {
			if req, isInt64 := reqArg.Value.(int64); isInt64 {
				ptraceRequestArgument, err := helpers.ParsePtraceRequestArgument(uint64(req))
				parseOrEmptyString(reqArg, ptraceRequestArgument, err)
			}
		}
	case Prctl:
		if optArg := GetArg(event, "option"); optArg != nil {
			if opt, isInt32 := optArg.Value.(int32); isInt32 {
				prctlOptionArgument, err := helpers.ParsePrctlOption(uint64(opt))
				parseOrEmptyString(optArg, prctlOptionArgument, err)
			}
		}
	case Socketcall:
		if callArg := GetArg(event, "call"); callArg != nil {
			if call, isInt32 := callArg.Value.(int32); isInt32 {
				socketcallArgument, err := helpers.ParseSocketcallCall(uint64(call))
				parseOrEmptyString(callArg, socketcallArgument, err)
			}
		}
	case Socket:
		if domArg := GetArg(event, "domain"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := helpers.ParseSocketDomainArgument(uint64(dom))
				parseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := helpers.ParseSocketType(uint64(typ))
				parseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case SecuritySocketCreate, SecuritySocketConnect:
		if domArg := GetArg(event, "family"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := helpers.ParseSocketDomainArgument(uint64(dom))
				parseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := helpers.ParseSocketType(uint64(typ))
				parseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case Access, Faccessat:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isInt32 := modeArg.Value.(int32); isInt32 {
				accessModeArgument, err := helpers.ParseAccessMode(uint64(mode))
				parseOrEmptyString(modeArg, accessModeArgument, err)
			}
		}
	case Execveat:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				execFlagArgument, err := helpers.ParseExecFlag(uint64(flags))
				parseOrEmptyString(flagsArg, execFlagArgument, err)
			}
		}
	case Open, Openat, SecurityFileOpen:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				openFlagArgument, err := helpers.ParseOpenFlagArgument(uint64(flags))
				parseOrEmptyString(flagsArg, openFlagArgument, err)
			}
		}
	case Mknod, Mknodat, Chmod, Fchmod, Fchmodat:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isUint32 := modeArg.Value.(uint32); isUint32 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case SecurityInodeMknod:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case Clone:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isUint64 := flagsArg.Value.(uint64); isUint64 {
				cloneFlagArgument, err := helpers.ParseCloneFlags(uint64(flags))
				parseOrEmptyString(flagsArg, cloneFlagArgument, err)
			}
		}
	case Bpf, SecurityBPF:
		if cmdArg := GetArg(event, "cmd"); cmdArg != nil {
			if cmd, isInt32 := cmdArg.Value.(int32); isInt32 {
				bpfCommandArgument, err := helpers.ParseBPFCmd(uint64(cmd))
				parseOrEmptyString(cmdArg, bpfCommandArgument, err)
			}
		}
	case SecurityKernelReadFile, SecurityPostReadFile:
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if readFileId, isInt32 := typeArg.Value.(trace.KernelReadType); isInt32 {
				emptyString(typeArg)
				typeArg.Value = readFileId.String()
			}
		}
	case SchedProcessExec:
		if modeArg := GetArg(event, "stdin_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case DirtyPipeSplice:
		if modeArg := GetArg(event, "in_file_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case SecuritySocketSetsockopt, Setsockopt, Getsockopt:
		if levelArg := GetArg(event, "level"); levelArg != nil {
			if level, isInt := levelArg.Value.(int32); isInt {
				levelArgument, err := helpers.ParseSocketLevel(uint64(level))
				parseOrEmptyString(levelArg, levelArgument, err)
			}
		}
		if optionNameArg := GetArg(event, "optname"); optionNameArg != nil {
			if opt, isInt := optionNameArg.Value.(int32); isInt {
				var optionNameArgument helpers.SocketOptionArgument
				var err error
				if ID(event.EventID) == Getsockopt {
					optionNameArgument, err = helpers.ParseGetSocketOption(uint64(opt))
				} else {
					optionNameArgument, err = helpers.ParseSetSocketOption(uint64(opt))
				}
				parseOrEmptyString(optionNameArg, optionNameArgument, err)
			}
		}
	case BpfAttach:
		if progTypeArg := GetArg(event, "prog_type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(int32); isInt {
				progTypeArgument, err := helpers.ParseBPFProgType(uint64(progType))
				parseOrEmptyString(progTypeArg, progTypeArgument, err)
			}
		}
		if helpersArg := GetArg(event, "prog_helpers"); helpersArg != nil {
			if helpersList, isUintSlice := helpersArg.Value.([]uint64); isUintSlice {
				parsedHelpersList, err := parseBpfHelpersUsage(helpersList)
				if err != nil {
					return err
				}
				helpersArg.Type = "const char**"
				helpersArg.Value = parsedHelpersList
			}
		}
		if attachTypeArg := GetArg(event, "attach_type"); attachTypeArg != nil {
			if attachType, isInt := attachTypeArg.Value.(int32); isInt {
				attachTypestr, err := parseBpfAttachType(attachType)
				emptyString(attachTypeArg)
				if err == nil {
					attachTypeArg.Value = attachTypestr
				}
			}
		}
	case SecurityBpfProg:
		if progTypeArg := GetArg(event, "type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(int32); isInt {
				progTypeArgument, err := helpers.ParseBPFProgType(uint64(progType))
				parseOrEmptyString(progTypeArg, progTypeArgument, err)
			}
		}
		if helpersArg := GetArg(event, "helpers"); helpersArg != nil {
			if helpersList, isUintSlice := helpersArg.Value.([]uint64); isUintSlice {
				parsedHelpersList, err := parseBpfHelpersUsage(helpersList)
				if err != nil {
					return err
				}
				helpersArg.Type = "const char**"
				helpersArg.Value = parsedHelpersList
			}
		}
	}

	return nil
}

func ParseArgsFDs(event *trace.Event, origTimestamp uint64, fdArgPathMap *bpf.BPFMap) error {
	if fdArg := GetArg(event, "fd"); fdArg != nil {
		if fd, isInt32 := fdArg.Value.(int32); isInt32 {
			ts := origTimestamp
			bs, err := fdArgPathMap.GetValue(unsafe.Pointer(&ts))
			if err != nil {
				return errfmt.WrapError(err)
			}

			fpath := string(bytes.Trim(bs, "\x00"))
			fdArg.Value = fmt.Sprintf("%d=%s", fd, fpath)
		}
	}

	return nil
}

func GetArg(event *trace.Event, argName string) *trace.Argument {
	for i := range event.Args {
		if event.Args[i].Name == argName {
			return &event.Args[i]
		}
	}
	return nil
}

type CustomFunctionArgument struct {
	val uint64
	str string
}

func (arg CustomFunctionArgument) String() string {
	return arg.str
}
func (arg CustomFunctionArgument) Value() uint64 {
	return arg.val
}

func parseBpfHelpersUsage(helpersList []uint64) ([]string, error) {
	var usedHelpers []string

	for i := 0; i < len(helpersList)*64; i++ {
		if (helpersList[i/64] & (1 << (i % 64))) > 0 {
			// helper number <i> is used. get its name from libbpfgo
			bpfHelper, err := helpers.ParseBPFFunc(uint64(i))
			if err != nil {
				continue
			}
			usedHelpers = append(usedHelpers, bpfHelper.String())
		}
	}

	return usedHelpers, nil
}

func parseBpfAttachType(attachType int32) (string, error) {
	switch attachType {
	case 0:
		return "raw_tracepoint", nil
	case 1:
		return "tracepoint", nil
	case 2:
		return "kprobe", nil
	case 3:
		return "kretprobe", nil
	case 4:
		return "uprobe", nil
	case 5:
		return "uretprobe", nil
	default:
		return "", errfmt.Errorf("unknown attach_type got from bpf_attach event")
	}
}

// parsing new event struct
func ParseArgs2(event *types.Event) error {
	// we can't do this with the new event struct, as we don't differentiate between pointer and int64
	// so how do we know here?
	// for i := range event.Args {
	// 	if ptr, isUintptr := event.Args[i].Value.(uintptr); isUintptr {
	// 		event.Args[i].Value = "0x" + strconv.FormatUint(uint64(ptr), 16)
	// 	}
	// }

	switch ID(event.GetId()) {
	case MemProtAlert:
		if index, alertArg := GetEventValue(event, "alert"); alertArg != nil {
			if alert, isUint32 := alertArg.Value.(*pb.EventValue_UInt32); isUint32 {
				event.Data[index].Value = &pb.EventValue_Str{
					Str: trace.MemProtAlert(alert.UInt32).String(),
				}
			}
		}
		if index, protArg := GetEventValue(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(*pb.EventValue_Int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot.Int32))
				event.Data[index].Value = &pb.EventValue_Str{
					Str: mmapProtArgument.String(),
				}
			}
		}
		if index, prevProtArg := GetEventValue(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(*pb.EventValue_Int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prevProt.Int32))
				event.Data[index].Value = &pb.EventValue_Str{
					Str: mmapProtArgument.String(),
				}
			}
		}
	case SysEnter, SysExit:
		if index, syscallArg := GetEventValue(event, "syscall"); syscallArg != nil {
			if id, isInt32 := syscallArg.Value.(*pb.EventValue_Int32); isInt32 {
				if Core.IsDefined(ID(id.Int32)) {
					eventDefinition := Core.GetDefinitionByID(ID(id.Int32))
					if eventDefinition.IsSyscall() {
						event.Data[index].Value = &pb.EventValue_Str{
							Str: eventDefinition.GetName(),
						}
					}
				}
			}
		}
	case CapCapable:
		if index, capArg := GetEventValue(event, "cap"); capArg != nil {
			if capability, isInt32 := capArg.Value.(*pb.EventValue_Int32); isInt32 {
				capabilityFlagArgument, err := helpers.ParseCapability(uint64(capability.Int32))

				var v string
				if err != nil {
					v = capabilityFlagArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case SecurityMmapFile, DoMmap:
		if index, protArg := GetEventValue(event, "prot"); protArg != nil {
			if prot, isUint64 := protArg.Value.(*pb.EventValue_UInt64); isUint64 {
				mmapProtArgument := helpers.ParseMmapProt(prot.UInt64)
				event.Data[index].Value = &pb.EventValue_Str{
					Str: mmapProtArgument.String(),
				}
			}
		}
	case Mmap, Mprotect, PkeyMprotect:
		if index, protArg := GetEventValue(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(*pb.EventValue_Int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot.Int32))
				event.Data[index].Value = &pb.EventValue_Str{
					Str: mmapProtArgument.String(),
				}
			}
		}
	case SecurityFileMprotect:
		if index, protArg := GetEventValue(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(*pb.EventValue_Int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot.Int32))
				event.Data[index].Value = &pb.EventValue_Str{
					Str: mmapProtArgument.String(),
				}
			}
		}
		if index, prevProtArg := GetEventValue(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(*pb.EventValue_Int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prevProt.Int32))
				event.Data[index].Value = &pb.EventValue_Str{
					Str: mmapProtArgument.String(),
				}
			}
		}
	case Ptrace:
		if index, reqArg := GetEventValue(event, "request"); reqArg != nil {
			if req, isInt64 := reqArg.Value.(*pb.EventValue_Int64); isInt64 {
				ptraceRequestArgument, err := helpers.ParsePtraceRequestArgument(uint64(req.Int64))

				var v string
				if err != nil {
					v = ptraceRequestArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case Prctl:
		if index, optArg := GetEventValue(event, "option"); optArg != nil {
			if opt, isInt32 := optArg.Value.(*pb.EventValue_Int32); isInt32 {
				prctlOptionArgument, err := helpers.ParsePrctlOption(uint64(opt.Int32))

				var v string
				if err != nil {
					v = prctlOptionArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case Socketcall:
		if index, callArg := GetEventValue(event, "call"); callArg != nil {
			if call, isInt32 := callArg.Value.(*pb.EventValue_Int32); isInt32 {
				socketcallArgument, err := helpers.ParseSocketcallCall(uint64(call.Int32))

				var v string
				if err != nil {
					v = socketcallArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case Socket:
		if index, domArg := GetEventValue(event, "domain"); domArg != nil {
			if dom, isInt32 := domArg.Value.(*pb.EventValue_Int32); isInt32 {
				socketDomainArgument, err := helpers.ParseSocketDomainArgument(uint64(dom.Int32))

				var v string
				if err != nil {
					v = socketDomainArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
		if index, typeArg := GetEventValue(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(*pb.EventValue_Int32); isInt32 {
				socketTypeArgument, err := helpers.ParseSocketType(uint64(typ.Int32))

				var v string
				if err != nil {
					v = socketTypeArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case SecuritySocketCreate, SecuritySocketConnect:
		if index, domArg := GetEventValue(event, "family"); domArg != nil {
			if dom, isInt32 := domArg.Value.(*pb.EventValue_Int32); isInt32 {
				socketDomainArgument, err := helpers.ParseSocketDomainArgument(uint64(dom.Int32))

				var v string
				if err != nil {
					v = socketDomainArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
		if index, typeArg := GetEventValue(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(*pb.EventValue_Int32); isInt32 {
				socketTypeArgument, err := helpers.ParseSocketType(uint64(typ.Int32))

				var v string
				if err != nil {
					v = socketTypeArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case Access, Faccessat:
		if index, modeArg := GetEventValue(event, "mode"); modeArg != nil {
			if mode, isInt32 := modeArg.Value.(*pb.EventValue_Int32); isInt32 {
				accessModeArgument, err := helpers.ParseAccessMode(uint64(mode.Int32))

				var v string
				if err != nil {
					v = accessModeArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case Execveat:
		if index, flagsArg := GetEventValue(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(*pb.EventValue_Int32); isInt32 {
				execFlagArgument, err := helpers.ParseExecFlag(uint64(flags.Int32))

				var v string
				if err != nil {
					v = execFlagArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case Open, Openat, SecurityFileOpen:
		if index, flagsArg := GetEventValue(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(*pb.EventValue_Int32); isInt32 {
				openFlagArgument, err := helpers.ParseOpenFlagArgument(uint64(flags.Int32))

				var v string
				if err != nil {
					v = openFlagArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case Mknod, Mknodat, Chmod, Fchmod, Fchmodat:
		if index, modeArg := GetEventValue(event, "mode"); modeArg != nil {
			if mode, isUint32 := modeArg.Value.(*pb.EventValue_UInt32); isUint32 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode.UInt32))

				var v string
				if err != nil {
					v = inodeModeArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case SecurityInodeMknod:
		if index, modeArg := GetEventValue(event, "mode"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(*pb.EventValue_UInt32); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode.UInt32))

				var v string
				if err != nil {
					v = inodeModeArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case Clone:
		if index, flagsArg := GetEventValue(event, "flags"); flagsArg != nil {
			if flags, isUint64 := flagsArg.Value.(*pb.EventValue_UInt64); isUint64 {
				cloneFlagArgument, err := helpers.ParseCloneFlags(uint64(flags.UInt64))

				var v string
				if err != nil {
					v = cloneFlagArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case Bpf, SecurityBPF:
		if index, cmdArg := GetEventValue(event, "cmd"); cmdArg != nil {
			if cmd, isInt32 := cmdArg.Value.(*pb.EventValue_Int32); isInt32 {
				bpfCommandArgument, err := helpers.ParseBPFCmd(uint64(cmd.Int32))

				var v string
				if err != nil {
					v = bpfCommandArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case SecurityKernelReadFile, SecurityPostReadFile:
		if index, typeArg := GetEventValue(event, "type"); typeArg != nil {
			if readFileId, isInt32 := typeArg.Value.(*pb.EventValue_UInt32); isInt32 {
				event.Data[index].Value = &pb.EventValue_Str{
					Str: trace.KernelReadType(readFileId.UInt32).String(),
				}
			}
		}
	case SchedProcessExec:
		if index, modeArg := GetEventValue(event, "stdin_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(*pb.EventValue_UInt32); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode.UInt32))

				var v string
				if err != nil {
					v = inodeModeArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case DirtyPipeSplice:
		if index, modeArg := GetEventValue(event, "in_file_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(*pb.EventValue_UInt32); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode.UInt32))

				var v string
				if err != nil {
					v = inodeModeArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case SecuritySocketSetsockopt, Setsockopt, Getsockopt:
		if index, levelArg := GetEventValue(event, "level"); levelArg != nil {
			if level, isInt := levelArg.Value.(*pb.EventValue_Int32); isInt {
				levelArgument, err := helpers.ParseSocketLevel(uint64(level.Int32))

				var v string
				if err != nil {
					v = levelArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
		if index, optionNameArg := GetEventValue(event, "optname"); optionNameArg != nil {
			if opt, isInt := optionNameArg.Value.(*pb.EventValue_Int32); isInt {
				var optionNameArgument helpers.SocketOptionArgument
				var err error
				if ID(event.Id) == Getsockopt {
					optionNameArgument, err = helpers.ParseGetSocketOption(uint64(opt.Int32))
				} else {
					optionNameArgument, err = helpers.ParseSetSocketOption(uint64(opt.Int32))
				}

				var v string
				if err != nil {
					v = optionNameArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case BpfAttach:
		if index, progTypeArg := GetEventValue(event, "prog_type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(*pb.EventValue_Int32); isInt {
				progTypeArgument, err := helpers.ParseBPFProgType(uint64(progType.Int32))

				var v string
				if err != nil {
					v = progTypeArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
		if index, helpersArg := GetEventValue(event, "prog_helpers"); helpersArg != nil {
			// TODO: needs fixing
			if helpersList, isUintSlice := helpersArg.Value.(*pb.EventValue_UInt64Array); isUintSlice {
				parsedHelpersList, err := parseBpfHelpersUsage(helpersList.UInt64Array.GetValue())
				if err != nil {
					return err
				}

				event.Data[index].Value = &pb.EventValue_StrArray{
					StrArray: &pb.StringArray{
						Value: parsedHelpersList,
					},
				}
			}
		}
		if index, attachTypeArg := GetEventValue(event, "attach_type"); attachTypeArg != nil {
			if attachType, isInt := attachTypeArg.Value.(*pb.EventValue_Int32); isInt {
				attachTypestr, err := parseBpfAttachType(attachType.Int32)

				var v string
				if err != nil {
					v = attachTypestr
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
	case SecurityBpfProg:
		if index, progTypeArg := GetEventValue(event, "type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(*pb.EventValue_Int32); isInt {
				progTypeArgument, err := helpers.ParseBPFProgType(uint64(progType.Int32))

				var v string
				if err != nil {
					v = progTypeArgument.String()
				}

				event.Data[index].Value = &pb.EventValue_Str{
					Str: v,
				}
			}
		}
		if index, helpersArg := GetEventValue(event, "helpers"); helpersArg != nil {
			if helpersList, isUintSlice := helpersArg.Value.(*pb.EventValue_UInt64Array); isUintSlice {
				parsedHelpersList, err := parseBpfHelpersUsage(helpersList.UInt64Array.GetValue())
				if err != nil {
					return err
				}
				event.Data[index].Value = &pb.EventValue_StrArray{
					StrArray: &pb.StringArray{
						Value: parsedHelpersList,
					},
				}
			}
		}
	}

	return nil
}

func ParseArgsFDs2(event *types.Event, origTimestamp uint64, fdArgPathMap *bpf.BPFMap) error {
	if index, fdArg := GetEventValue(event, "fd"); fdArg != nil {
		if fd, isInt32 := fdArg.Value.(*pb.EventValue_Int32); isInt32 {
			ts := origTimestamp
			bs, err := fdArgPathMap.GetValue(unsafe.Pointer(&ts))
			if err != nil {
				return errfmt.WrapError(err)
			}

			fpath := string(bytes.Trim(bs, "\x00"))

			event.Data[index].Value = &pb.EventValue_Str{
				Str: fmt.Sprintf("%d=%s", fd, fpath),
			}
		}
	}

	return nil
}

// SHOULD THIS BE EXPORTED?
func GetEventValue(event *types.Event, argName string) (int, *pb.EventValue) {
	for i, d := range event.GetData() {
		if d.Name == argName {
			return i, d
		}
	}
	return -1, nil
}
