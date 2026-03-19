module github.com/AKiileX/Phantex/gateway

go 1.24.0

replace github.com/AKiileX/Phantex/proto/gen/go => ../proto/gen/go

require (
	github.com/AKiileX/Phantex/proto/gen/go v0.0.0-00010101000000-000000000000
	github.com/segmentio/kafka-go v0.4.47
	go.uber.org/zap v1.27.0
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.10
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
)
