package derive

import (
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/types"
)

// ContainerRemove receives a containers.Containers object as a closure argument to track it's containers.
// If it receives a cgroup_rmdir event, it can derive a container_remove event from it.
func ContainerRemove(cts *containers.Containers) DeriveFunction {
	return deriveSingleEvent(events.ContainerRemove, deriveContainerRemoveArgs(cts))
}

func deriveContainerRemoveArgs(cts *containers.Containers) deriveArgsFunction {
	return func(event *types.Event) ([]interface{}, error) {
		// if cgroup_id is from non default hid (v1 case), the cgroup info query will fail, so we skip
		if check, err := isCgroupEventInHid(event, cts); !check {
			return nil, errfmt.WrapError(err)
		}

		var cgroupId uint64

		for _, ev := range event.GetData() {
			if ev.Name == "cgroup_id" {
				cgroupId = ev.GetUInt64()
			}
		}

		if info := cts.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
			return []interface{}{info.Runtime.String(), info.Container.ContainerId}, nil
		}
		return nil, nil
	}
}
