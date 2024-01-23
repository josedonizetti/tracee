package helpers

import (
	b64 "encoding/base64"
	"fmt"

	"github.com/aquasecurity/tracee/pkg/types"
	"github.com/aquasecurity/tracee/types/trace"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

// GetArgOps represents options for arguments getters
type GetArgOps struct {
	DefaultArgs bool // Receive default args value (value equals 'nil'). If set to false, will return error if arg not initialized.
}

// GetTraceeArgumentByName fetches the argument in event with `Name` that matches argName
func GetTraceeArgumentByName(event *types.Event, argName string, opts GetArgOps) (*pb.EventValue, error) {
	for _, arg := range event.GetData() {
		if arg.Name == argName {
			if !opts.DefaultArgs && arg.Value == nil {
				return arg, fmt.Errorf("argument %s is not initialized", argName)
			}
			return arg, nil
		}
	}
	return nil, fmt.Errorf("argument %s not found", argName)
}

// GetTraceeStringArgumentByName gets the argument matching the "argName" given from the event "argv" field, casted as string.
func GetTraceeStringArgumentByName(event *types.Event, argName string) (string, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return "", err
	}
	argStr, ok := arg.Value.(*pb.EventValue_Str)
	if ok {
		return argStr.Str, nil
	}

	return "", fmt.Errorf("can't convert argument %v to string", argName)
}

// GetTraceeIntArgumentByName gets the argument matching the "argName" given from the event "argv" field, casted as int.
func GetTraceeIntArgumentByName(event *types.Event, argName string) (int, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return 0, err
	}
	argInt, ok := arg.Value.(*pb.EventValue_Int32)
	if ok {
		return int(argInt.Int32), nil
	}

	return 0, fmt.Errorf("can't convert argument %v to int", argName)
}

// GetTraceeSliceStringArgumentByName gets the argument matching the "argName" given from the event "argv" field, casted as []string.
func GetTraceeSliceStringArgumentByName(event *types.Event, argName string) ([]string, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}

	argStr, ok := arg.Value.(*pb.EventValue_StrArray)
	if ok {
		return argStr.StrArray.GetValue(), nil
	}

	return nil, fmt.Errorf("can't convert argument %v to slice of strings", argName)
}

// GetTraceeBytesSliceArgumentByName gets the argument matching the "argName" given from the event "argv" field, casted as []byte.
func GetTraceeBytesSliceArgumentByName(event *types.Event, argName string) ([]byte, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}
	argBytes, ok := arg.Value.(*pb.EventValue_Bytes)
	if ok {
		return argBytes.Bytes, nil
	}

	argBytesString, ok := arg.Value.(*pb.EventValue_Str)
	if ok {
		decodedBytes, err := b64.StdEncoding.DecodeString(argBytesString.Str)
		if err != nil {
			return nil, fmt.Errorf("can't convert argument %v to []bytes", argName)
		}
		return decodedBytes, nil
	}

	return nil, fmt.Errorf("can't convert argument %v to []bytes", argName)
}

// TODO: fix me
// TODO: is this used? because we dont have map[string]string arguments I think
func GetRawAddrArgumentByName(event *types.Event, argName string) (map[string]string, error) {
	return map[string]string{}, nil
	// arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	// if err != nil {
	// 	return nil, err
	// }

	// addr, isOk := arg.Value.(map[string]string)
	// if !isOk {
	// 	addr = make(map[string]string)
	// 	stringInterMap, isStringInterMap := arg.Value.(map[string]interface{})
	// 	if !isStringInterMap {
	// 		return addr, fmt.Errorf("couldn't convert arg to addr")
	// 	}
	// 	for k, v := range stringInterMap {
	// 		s, isString := v.(string)
	// 		if !isString {
	// 			return addr, fmt.Errorf("couldn't convert arg to addr")
	// 		}
	// 		addr[k] = s
	// 	}
	// }
	// return addr, nil
}

func GetTraceeHookedSymbolDataArgumentByName(event *types.Event, argName string) ([]*pb.HookedSymbolData, error) {
	hookedSymbolsPtr, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}

	hookedSyscalls, ok := hookedSymbolsPtr.Value.(*pb.EventValue_HookedSyscalls)
	if ok {
		return hookedSyscalls.HookedSyscalls.GetValue(), nil
	}

	// TODO: fix me
	// var hookedSymbols []*pb.HookedSymbolData

	// hmm, this wouldn't happen with the new implementation
	// when can this be an []interface{}
	// argSlice, ok := hookedSymbolsPtr.Value.([]interface{})
	// if ok {
	// 	for _, v := range argSlice {
	// 		hookedSymbol, err := getHookedSymbolData(v)
	// 		if err != nil {
	// 			continue
	// 		}
	// 		hookedSymbols = append(hookedSymbols, hookedSymbol)
	// 	}
	// 	return hookedSymbols, nil
	// }

	return nil, fmt.Errorf("can't convert argument %v to []trace.HookedSymbolData", argName)
}

// getHookedSymbolData generates a trace.HookedSymbolData from interface{} got from event arg
func getHookedSymbolData(v interface{}) (trace.HookedSymbolData, error) {
	symbol := trace.HookedSymbolData{}

	hookedSymbolMap, ok := v.(map[string]interface{})
	if !ok {
		return symbol, fmt.Errorf("can't convert hooked symbol to map[string]interface{}")
	}

	for key, value := range hookedSymbolMap {
		strValue, ok := value.(string)
		if !ok {
			continue
		}
		switch key {
		case "ModuleOwner":
			symbol.ModuleOwner = strValue
		case "SymbolName":
			symbol.SymbolName = strValue
		}
	}

	return symbol, nil
}
