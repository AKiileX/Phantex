module github.com/AKiileX/Phantex/sensor

go 1.23.6

require (
	github.com/AKiileX/Phantex/proto/gen/go v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.17.3
	github.com/prometheus/client_golang v1.23.2
	go.uber.org/zap v1.27.0
	golang.org/x/sys v0.35.0
	google.golang.org/grpc v1.68.1
	google.golang.org/protobuf v1.36.8
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240903143218-8af14fe29dc1 // indirect
)

replace github.com/AKiileX/Phantex/proto/gen/go => ../proto/gen/go
