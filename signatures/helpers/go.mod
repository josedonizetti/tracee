module github.com/aquasecurity/tracee/signatures/helpers

go 1.21

require (
	github.com/aquasecurity/tracee/api v0.0.0-20240118133111-07e087b036d4
	github.com/aquasecurity/tracee/types v0.0.0-20240122122429-7f84f526758d
)

require (
	github.com/aquasecurity/tracee v0.19.0
	github.com/golang/protobuf v1.5.3 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230920204549-e6e6cdab5c13 // indirect
	google.golang.org/grpc v1.58.3 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

replace github.com/aquasecurity/tracee v0.19.0 => github.com/josedonizetti/tracee v0.16.0-rc.0.20240126124143-459e11f13893
