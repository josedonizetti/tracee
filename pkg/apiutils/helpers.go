package apiutils

import (
	"fmt"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/types"
)

func GetReturnValue(event *types.Event) (int64, error) {
	ev, err := getArg(event, "returnValue")
	if err != nil {
		return 0, err
	}

	return ev.GetInt64(), nil
}

func GetInt32Arg(event *types.Event, arg string) (int32, error) {
	ev, err := getArg(event, arg)
	if err != nil {
		return 0, err
	}

	return ev.GetInt32(), nil
}

func GetUInt32Arg(event *types.Event, arg string) (uint32, error) {
	ev, err := getArg(event, arg)
	if err != nil {
		return 0, err
	}

	return ev.GetUInt32(), nil
}

func GetUInt64Arg(event *types.Event, arg string) (uint64, error) {
	ev, err := getArg(event, arg)
	if err != nil {
		return 0, err
	}

	return ev.GetUInt64(), nil
}

func GetBytesArg(event *types.Event, arg string) ([]byte, error) {
	ev, err := getArg(event, arg)
	if err != nil {
		return nil, err
	}

	return ev.GetBytes(), nil
}

func GetUInt64ArrayArg(event *types.Event, arg string) ([]uint64, error) {
	ev, err := getArg(event, arg)
	if err != nil {
		return nil, err
	}

	return ev.GetUInt64Array().GetValue(), nil

}

func GetStringArg(event *types.Event, arg string) (string, error) {
	ev, err := getArg(event, arg)
	if err != nil {
		return "", err
	}

	return ev.GetStr(), nil
}

func GetMapStringStringArg(event *types.Event, arg string) (map[string]string, error) {
	_, err := getArg(event, arg)
	if err != nil {
		return nil, err
	}

	// TODO: josedonizetti fix me
	return map[string]string{}, nil
}

func getArg(event *types.Event, arg string) (*pb.EventValue, error) {
	for _, ev := range event.GetData() {
		if ev.Name == arg {
			return ev, nil
		}
	}
	return nil, fmt.Errorf("no argument %v found", arg)
}
