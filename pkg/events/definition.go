package events

import (
	"github.com/aquasecurity/tracee/types/trace"
)

type Definition struct {
	id           ID // TODO: use id ?
	id32Bit      ID
	name         string
	docPath      string // Relative to the 'doc/events' directory
	internal     bool
	syscall      bool
	dependencies Dependencies
	sets         []string
	params       []trace.ArgMeta
	metadata     Metadata
}

type Metadata struct {
	description string
	severity    string
	tags        []string
	misc        map[string]string
}

func NewMetadata(description, severity string, tags []string, misc map[string]string) Metadata {
	return Metadata{
		description: description,
		severity:    severity,
		tags:        tags,
		misc:        misc,
	}
}

func NewDefinition(
	id ID,
	id32Bit ID,
	name string,
	docPath string,
	internal bool,
	syscall bool,
	sets []string,
	deps Dependencies,
	params []trace.ArgMeta,
) Definition {
	return Definition{
		id:           id,
		id32Bit:      id32Bit,
		name:         name,
		docPath:      docPath,
		internal:     internal,
		syscall:      syscall,
		dependencies: deps,
		sets:         sets,
		params:       params,
	}
}

func NewDefinitionWithMetadata(
	id ID,
	id32Bit ID,
	name string,
	docPath string,
	internal bool,
	syscall bool,
	sets []string,
	deps Dependencies,
	params []trace.ArgMeta,
	metadata Metadata,
) Definition {
	return Definition{
		id:           id,
		id32Bit:      id32Bit,
		name:         name,
		docPath:      docPath,
		internal:     internal,
		syscall:      syscall,
		dependencies: deps,
		sets:         sets,
		params:       params,
		metadata:     metadata,
	}
}

// Getters (immutable data)

func (d Definition) GetID() ID {
	return d.id
}

func (d Definition) GetID32Bit() ID {
	return d.id32Bit
}

func (d Definition) GetName() string {
	return d.name
}

func (d Definition) GetDocPath() string {
	return d.docPath
}

func (d Definition) IsInternal() bool {
	return d.internal
}

func (d Definition) IsSyscall() bool {
	return d.syscall
}

func (d Definition) GetDependencies() Dependencies {
	return d.dependencies
}

func (d Definition) GetSets() []string {
	return d.sets
}

func (d Definition) GetParams() []trace.ArgMeta {
	return d.params
}

func (d Definition) GetMetadata() Metadata {
	return d.metadata
}

func (d Definition) IsSignature() bool {
	if d.id >= StartSignatureID && d.id <= MaxSignatureID {
		return true
	}

	return false
}

func (d Definition) IsNetwork() bool {
	if d.id >= NetPacketIPv4 && d.id <= MaxUserNetID {
		return true
	}

	return false
}

func (m Metadata) GetDescription() string {
	return m.description
}

func (m Metadata) GetSeverity() string {
	return m.severity
}

func (m Metadata) GetTags() []string {
	return m.tags
}

func (m Metadata) GetMisc() map[string]string {
	return m.misc
}
