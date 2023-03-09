package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
)

type PolicyFile struct {
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	Scope         []string `yaml:"scope"`
	DefaultAction string   `yaml:"default_action"`
	Rules         []Rule   `yaml:"rules"`
}

type Rule struct {
	Event  string   `yaml:"event"`
	Filter []string `yaml:"filter"`
	Action string   `yaml:"action"`
}

// receive array of policies
func PrepareFilterMapForPolicies(policies []PolicyFile) (FilterMap, error) {
	filterMap := make(FilterMap)

	if len(policies) == 0 {
		return nil, errfmt.Errorf("no policies provided")
	}

	if len(policies) > 64 {
		return nil, errfmt.Errorf("too many policies provided, there is a limit of 64 policies")
	}

	for i, p := range policies {
		err := validatePolicy(p)
		if err != nil {
			return nil, err
		}

		filterFlags := make([]*filterFlag, 0)

		if p.Scope == nil {
			return nil, errfmt.Errorf("policy scope cannot be empty")
		}

		// scope
		for _, s := range p.Scope {
			if s == "global" {
				break
			}

			var scope, filterName, operatorAndValues string

			switch s {
			case "follow", "!container":
				scope = s
				filterName = s
				operatorAndValues = ""
			default:
				operatorIdx := strings.IndexAny(s, "=!<>")

				if operatorIdx == -1 {
					return nil, errfmt.Errorf("policy %s, scope %s is not valid", p.Name, s)
				}

				scope = s[:operatorIdx]
				filterName = s[:operatorIdx]
				operatorAndValues = s[operatorIdx:]
			}

			err := validateScope(p.Name, scope)
			if err != nil {
				return nil, err
			}

			filterFlags = append(filterFlags, &filterFlag{
				full:              s,
				filterName:        filterName,
				operatorAndValues: operatorAndValues,
				policyIdx:         i,
			})
		}

		for _, r := range p.Rules {
			err := validateEvent(p.Name, r.Event)
			if err != nil {
				return nil, err
			}

			filterFlags = append(filterFlags, &filterFlag{
				full:              fmt.Sprintf("event=%s", r.Event),
				filterName:        "event",
				operatorAndValues: fmt.Sprintf("=%s", r.Event),
				policyIdx:         i,
			})

			for _, f := range r.Filter {
				operatorIdx := strings.IndexAny(f, "=!<>")

				if operatorIdx == -1 {
					return nil, errfmt.Errorf("invalid filter: %s", f)
				}

				// args
				if strings.HasPrefix(f, "args.") {
					filterFlags = append(filterFlags, &filterFlag{
						full:              fmt.Sprintf("%s.%s", r.Event, f),
						filterName:        fmt.Sprintf("%s.%s", r.Event, f[:operatorIdx]),
						operatorAndValues: f[operatorIdx:],
						policyIdx:         i,
					})

					continue
				}

				// retval
				if strings.HasPrefix(f, "retval.") {
					filterFlags = append(filterFlags, &filterFlag{
						full:              fmt.Sprintf("%s.retval.%s", r.Event, f),
						filterName:        fmt.Sprintf("%s.retval.%s", r.Event, f[:operatorIdx]),
						operatorAndValues: f[operatorIdx:],
						policyIdx:         i,
					})
					continue
				}

				err = validateContext(p.Name, f[:operatorIdx])
				if err != nil {
					return nil, err
				}

				// context
				filterFlags = append(filterFlags, &filterFlag{
					full:              fmt.Sprintf("%s.context.%s", r.Event, f),
					filterName:        fmt.Sprintf("%s.context.%s", r.Event, f[:operatorIdx]),
					operatorAndValues: f[operatorIdx:],
					policyIdx:         i,
				})
			}
		}

		filterMap[i] = filterFlags
	}

	return filterMap, nil
}

func validatePolicy(p PolicyFile) error {
	if p.Name == "" {
		return errfmt.Errorf("policy name cannot be empty")
	}

	if p.Description == "" {
		return errfmt.Errorf("policy %s, description cannot be empty", p.Name)
	}

	if p.Scope == nil || len(p.Scope) == 0 {
		return errfmt.Errorf("policy %s, scope cannot be empty", p.Name)
	}

	if p.Rules == nil || len(p.Rules) == 0 {
		return errfmt.Errorf("policy %s, rules cannot be empty", p.Name)
	}

	return nil
}

func validateScope(policyName, s string) error {
	scopes := []string{
		"uid",
		"pid",
		"mntNS",
		"pidns",
		"uts",
		"comm",
		"container",
		"!container",
		"tree",
		"binary",
		"bin",
		"follow",
	}

	for _, scope := range scopes {
		if s == scope {
			return nil
		}
	}

	return errfmt.Errorf("policy %s, scope %s is not valid", policyName, s)
}

func validateEvent(policyName, eventName string) error {
	if eventName == "" {
		return errfmt.Errorf("policy %s, event cannot be empty", policyName)
	}

	_, ok := events.Definitions.GetID(eventName)
	if !ok {
		return errfmt.Errorf("policy %s, event %s is not valid", policyName, eventName)
	}
	return nil
}

func validateContext(policyName, c string) error {
	contexts := []string{
		"timestamp",
		"processorId",
		"p",
		"pid",
		"processId",
		"tid",
		"threadId",
		"ppid",
		"parentProcessId",
		"hostTid",
		"hostThreadId",
		"hostPid",
		"hostParentProcessId",
		"uid",
		"userId",
		"mntns",
		"mountNamespace",
		"pidns",
		"pidNamespace",
		"processName",
		"comm",
		"hostName",
		"cgroupId",
		"host",
		"container",
		"containerId",
		"containerImage",
		"containerName",
		"podName",
		"podNamespace",
		"podUid",
		"syscall",
	}

	for _, context := range contexts {
		if c == context {
			return nil
		}
	}

	return errfmt.Errorf("policy %s, filter %s is not valid", policyName, c)
}
