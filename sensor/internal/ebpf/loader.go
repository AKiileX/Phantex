// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package ebpf — loader.go
//
// Loads compiled eBPF .bpf.o programs into the kernel using cilium/ebpf.
// Each probe is loaded independently — if one fails, the sensor degrades
// gracefully instead of crashing (ADR-011).
//
// The .bpf.o files are embedded in the binary via go:embed (ADR-012).
package ebpf

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

//go:embed bpf
var bpfObjects embed.FS

// PinPath is where BPF maps are pinned for sharing across probe programs.
const PinPath = "/sys/fs/bpf/phantex"

// ProbeStatus tracks whether each probe loaded successfully.
type ProbeStatus struct {
	Name   string
	Loaded bool
	Error  error
}

// Loader manages the lifecycle of all eBPF programs and maps.
type Loader struct {
	mu     sync.Mutex
	log    *zap.Logger
	links  []link.Link        // attached probe links (for cleanup)
	colls  []*ebpf.Collection // loaded collections (for cleanup)
	probes []ProbeStatus      // per-probe load status
	// Shared maps (from the first successfully loaded collection)
	EventsMap    *ebpf.Map
	PidFilterMap *ebpf.Map
	ConfigMap    *ebpf.Map
}

// NewLoader creates a new eBPF probe loader.
func NewLoader(log *zap.Logger) *Loader {
	return &Loader{
		log: log,
	}
}

// probeSpec defines a single eBPF probe to load.
type probeSpec struct {
	name     string // human-readable name
	objFile  string // filename inside bpf/ directory
	programs []programAttach
	fallback *probeSpec // optional fallback if primary fails to load
}

// programAttach describes how to attach a single eBPF program within a collection.
type programAttach struct {
	progName   string     // ELF section / program name in the .o
	attachType attachKind // how to attach
	attachTo   string     // tracepoint name or kprobe symbol
}

type attachKind int

const (
	attachTracepoint attachKind = iota
	attachKprobe
	attachKretprobe
)

// allProbes defines every probe we attempt to load.
// Order doesn't matter — each is independent.
func allProbes() []probeSpec {
	return []probeSpec{
		{
			name:    "execve",
			objFile: "execve.bpf.o",
			programs: []programAttach{
				{progName: "tracepoint__syscalls__sys_enter_execve", attachType: attachTracepoint, attachTo: "syscalls/sys_enter_execve"},
				{progName: "tracepoint__syscalls__sys_exit_execve", attachType: attachTracepoint, attachTo: "syscalls/sys_exit_execve"},
			},
		},
		{
			name:    "openat",
			objFile: "openat.bpf.o",
			programs: []programAttach{
				{progName: "tracepoint__syscalls__sys_enter_openat", attachType: attachTracepoint, attachTo: "syscalls/sys_enter_openat"},
				{progName: "tracepoint__syscalls__sys_exit_openat", attachType: attachTracepoint, attachTo: "syscalls/sys_exit_openat"},
			},
		},
		{
			name:    "tcp_connect",
			objFile: "tcp_connect.bpf.o",
			programs: []programAttach{
				{progName: "kprobe__tcp_connect", attachType: attachKprobe, attachTo: "tcp_connect"},
				{progName: "kretprobe__inet_csk_accept", attachType: attachKretprobe, attachTo: "inet_csk_accept"},
			},
		},
		{
			name:    "write_read",
			objFile: "write_read.bpf.o",
			programs: []programAttach{
				{progName: "tracepoint__syscalls__sys_enter_write", attachType: attachTracepoint, attachTo: "syscalls/sys_enter_write"},
				{progName: "tracepoint__syscalls__sys_enter_read", attachType: attachTracepoint, attachTo: "syscalls/sys_enter_read"},
			},
		},
		{
			name:    "mmap",
			objFile: "mmap.bpf.o",
			programs: []programAttach{
				{progName: "tracepoint__syscalls__sys_enter_mmap", attachType: attachTracepoint, attachTo: "syscalls/sys_enter_mmap"},
			},
		},
		{
			name:    "dns",
			objFile: "dns.bpf.o",
			programs: []programAttach{
				{progName: "kprobe__udp_sendmsg", attachType: attachKprobe, attachTo: "udp_sendmsg"},
			},
			fallback: &probeSpec{
				name:    "dns",
				objFile: "dns_lite.bpf.o",
				programs: []programAttach{
					{progName: "kprobe__udp_sendmsg", attachType: attachKprobe, attachTo: "udp_sendmsg"},
				},
			},
		},
	}
}

// LoadAll loads and attaches all eBPF probes.
// Returns the number of successfully loaded probes.
// The sensor continues even if some probes fail (graceful degradation).
func (l *Loader) LoadAll() (loaded int, total int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Ensure pin path exists
	if err := os.MkdirAll(PinPath, 0700); err != nil {
		l.log.Warn("could not create BPF pin path (maps won't be pinned)",
			zap.String("path", PinPath), zap.Error(err))
	}

	specs := allProbes()
	total = len(specs)

	for _, spec := range specs {
		status := ProbeStatus{Name: spec.name}

		if err := l.loadProbe(spec); err != nil {
			// Try fallback if available (e.g., dns_lite for kernels
			// where the full DNS probe exceeds verifier limits)
			if spec.fallback != nil {
				l.log.Debug("probe primary failed, trying fallback",
					zap.String("probe", spec.name),
					zap.String("fallback", spec.fallback.objFile))
				if fbErr := l.loadProbe(*spec.fallback); fbErr == nil {
					status.Loaded = true
					loaded++
					l.log.Debug("fallback probe loaded",
						zap.String("probe", spec.name),
						zap.String("via", spec.fallback.objFile))
					l.probes = append(l.probes, status)
					continue
				} else {
					l.log.Warn("fallback probe also failed",
						zap.String("probe", spec.name),
						zap.Error(fbErr))
				}
			}
			status.Error = err
			l.log.Warn("probe failed to load — sensor degraded",
				zap.String("probe", spec.name),
				zap.Error(err))
		} else {
			status.Loaded = true
			loaded++
			l.log.Debug("probe loaded",
				zap.String("probe", spec.name))
		}

		l.probes = append(l.probes, status)
	}

	return loaded, total
}

// loadProbe loads a single probe's .o file, verifies its Ed25519
// signature, and attaches its programs.
func (l *Loader) loadProbe(spec probeSpec) error {
	// Read embedded .o file
	data, err := bpfObjects.ReadFile(filepath.Join("bpf", spec.objFile))
	if err != nil {
		return fmt.Errorf("read embedded object %s: %w", spec.objFile, err)
	}

	// Read companion .sig file (may not exist in dev builds)
	sigPath := filepath.Join("bpf", spec.objFile+".sig")
	sig, sigErr := bpfObjects.ReadFile(sigPath)
	if sigErr != nil {
		sig = nil // handled by verifyOrSkip
	}

	// Ed25519 signature verification (ADR-014)
	if err := verifyOrSkip(l.log, spec.objFile, data, sig); err != nil {
		return err
	}

	// Parse the ELF
	collSpec, err := ebpf.LoadCollectionSpecFromReader(bytesReader(data))
	if err != nil {
		return fmt.Errorf("parse ELF %s: %w", spec.objFile, err)
	}

	// Mark shared maps for pin-by-name so all probes reuse the same
	// ring buffer, PID filter, and config maps via the bpffs pin path.
	if err := l.rewriteMaps(collSpec); err != nil {
		return fmt.Errorf("rewrite maps for %s: %w", spec.name, err)
	}

	// Load into kernel
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: PinPath,
		},
	}
	coll, err := ebpf.NewCollectionWithOptions(collSpec, opts)
	if err != nil {
		return fmt.Errorf("load collection %s: %w", spec.name, err)
	}
	l.colls = append(l.colls, coll)

	// Capture shared maps from the first loaded collection
	if l.EventsMap == nil {
		l.captureSharedMaps(coll)
	}

	// Attach each program
	for _, pa := range spec.programs {
		prog, ok := coll.Programs[pa.progName]
		if !ok {
			return fmt.Errorf("program %q not found in %s", pa.progName, spec.objFile)
		}

		lnk, err := l.attachProgram(prog, pa)
		if err != nil {
			return fmt.Errorf("attach %q: %w", pa.progName, err)
		}
		l.links = append(l.links, lnk)
	}

	return nil
}

// attachProgram attaches a single eBPF program based on its attach type.
func (l *Loader) attachProgram(prog *ebpf.Program, pa programAttach) (link.Link, error) {
	switch pa.attachType {
	case attachTracepoint:
		// attachTo format: "category/name" e.g., "syscalls/sys_enter_execve"
		parts := splitTracepoint(pa.attachTo)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tracepoint format: %s", pa.attachTo)
		}
		return link.Tracepoint(parts[0], parts[1], prog, nil)

	case attachKprobe:
		return link.Kprobe(pa.attachTo, prog, nil)

	case attachKretprobe:
		return link.Kretprobe(pa.attachTo, prog, nil)

	default:
		return nil, fmt.Errorf("unknown attach type: %d", pa.attachType)
	}
}

// captureSharedMaps grabs references to the shared maps from the first loaded collection.
func (l *Loader) captureSharedMaps(coll *ebpf.Collection) {
	if m, ok := coll.Maps["events"]; ok {
		l.EventsMap = m
	}
	if m, ok := coll.Maps["pid_filter"]; ok {
		l.PidFilterMap = m
	}
	if m, ok := coll.Maps["config_map"]; ok {
		l.ConfigMap = m
	}
}

// rewriteMaps makes a collection spec share maps with the already-loaded first collection.
func (l *Loader) rewriteMaps(spec *ebpf.CollectionSpec) error {
	for name, mapSpec := range spec.Maps {
		switch name {
		case "events":
			mapSpec.Pinning = ebpf.PinByName
			spec.Maps[name] = mapSpec
		case "pid_filter":
			mapSpec.Pinning = ebpf.PinByName
			spec.Maps[name] = mapSpec
		case "config_map":
			mapSpec.Pinning = ebpf.PinByName
			spec.Maps[name] = mapSpec
		}
	}
	return nil
}

// Probes returns the load status of all probes.
func (l *Loader) Probes() []ProbeStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]ProbeStatus, len(l.probes))
	copy(out, l.probes)
	return out
}

// LoadedCount returns (loaded, total) probe counts.
func (l *Loader) LoadedCount() (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	loaded := 0
	for _, p := range l.probes {
		if p.Loaded {
			loaded++
		}
	}
	return loaded, len(l.probes)
}

// Close detaches all probes, closes maps, and cleans up.
func (l *Loader) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, lnk := range l.links {
		if err := lnk.Close(); err != nil {
			l.log.Warn("failed to close link", zap.Error(err))
		}
	}
	l.links = nil

	for _, coll := range l.colls {
		coll.Close()
	}
	l.colls = nil

	// Clean up pinned maps
	_ = os.RemoveAll(PinPath)

	l.log.Info("all eBPF probes detached and cleaned up")
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func splitTracepoint(s string) []string {
	for i, c := range s {
		if c == '/' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

// bytesReader wraps a byte slice to implement io.ReaderAt.
type bytesReaderAt struct {
	data []byte
}

func (r *bytesReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n = copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func bytesReader(data []byte) *bytesReaderAt {
	return &bytesReaderAt{data: data}
}
