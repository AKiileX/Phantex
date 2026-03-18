// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package discovery identifies AI agent processes running on the host.
//
// signatures.go defines the framework fingerprints used to classify a
// process as an AI agent (LangChain, AutoGen, CrewAI, Phantex SDK, etc.).
//
// Detection methods (in order of reliability):
//  1. /proc/<pid>/maps — loaded shared objects / Python module paths
//  2. /proc/<pid>/cmdline — command-line arguments (e.g., -m langchain)
//  3. /proc/<pid>/environ — environment variables set by frameworks
//
// Each signature has a confidence score. A process needs ≥1 high-confidence
// match to be classified as an AI agent.
package discovery

import "path/filepath"

// Framework identifies a known AI agent framework.
type Framework string

const (
	FrameworkLangChain  Framework = "langchain"
	FrameworkAutoGen    Framework = "autogen"
	FrameworkCrewAI     Framework = "crewai"
	FrameworkLlamaIndex Framework = "llamaindex"
	FrameworkPhantexSDK Framework = "phantex-sdk"
	FrameworkOpenAI     Framework = "openai-agents" // OpenAI Agents SDK
	FrameworkAnthropic  Framework = "anthropic"     // Anthropic SDK / Claude Code
	FrameworkOllama     Framework = "ollama"        // Ollama local LLM runner
	FrameworkLMStudio   Framework = "lm-studio"     // LM Studio desktop app
	FrameworkLlamaCpp   Framework = "llama-cpp"     // llama.cpp / llama-server
	FrameworkLocalAI    Framework = "localai"       // LocalAI server
	FrameworkGPT4All    Framework = "gpt4all"       // GPT4All desktop
	FrameworkJan        Framework = "jan"           // Jan AI desktop
	FrameworkKoboldCpp  Framework = "koboldcpp"     // KoboldCpp
	FrameworkMCP        Framework = "mcp"           // MCP (Model Context Protocol) servers/clients
	FrameworkWatchlist  Framework = "watchlist"     // User-configured binary patterns
	FrameworkUnknown    Framework = "unknown"
)

// Confidence indicates how certain we are about a framework match.
type Confidence int

const (
	ConfidenceLow    Confidence = 1 // might be the framework (e.g., openai in cmdline)
	ConfidenceMedium Confidence = 2 // likely the framework (e.g., module in maps)
	ConfidenceHigh   Confidence = 3 // definitely the framework (e.g., specific entry point)
)

// Signature defines a single detection pattern for a framework.
type Signature struct {
	Framework  Framework
	Source     SignatureSource // where to look
	Pattern    string          // substring to match (case-insensitive for cmdline/environ)
	Confidence Confidence
}

// SignatureSource indicates which /proc file to search.
type SignatureSource int

const (
	SourceMaps         SignatureSource = iota // /proc/<pid>/maps — loaded libraries/modules
	SourceCmdline                             // /proc/<pid>/cmdline — command line
	SourceEnviron                             // /proc/<pid>/environ — environment variables
	SourceSitePackages                        // Python site-packages directory scanning
)

func (s SignatureSource) String() string {
	switch s {
	case SourceMaps:
		return "maps"
	case SourceCmdline:
		return "cmdline"
	case SourceEnviron:
		return "environ"
	case SourceSitePackages:
		return "site-packages"
	default:
		return "unknown"
	}
}

// BuiltinSignatures returns all framework detection signatures.
// These are ordered by confidence (high first) for early exit during scanning.
//
// Adding a new framework:
//  1. Add a Framework constant above
//  2. Add signatures here (at least one ConfidenceHigh)
//  3. That's it — the scanner picks them up automatically
func BuiltinSignatures() []Signature {
	return []Signature{
		// ── LangChain ──────────────────────────────────────────────────
		// High: LangChain-specific modules in memory maps
		{FrameworkLangChain, SourceMaps, "langchain_core", ConfidenceHigh},
		{FrameworkLangChain, SourceMaps, "langchain/", ConfidenceHigh},
		{FrameworkLangChain, SourceMaps, "langgraph/", ConfidenceHigh},
		// Medium: cmdline indicators
		{FrameworkLangChain, SourceCmdline, "langchain", ConfidenceMedium},
		{FrameworkLangChain, SourceCmdline, "langgraph", ConfidenceMedium},
		// Low: environment variable
		{FrameworkLangChain, SourceEnviron, "LANGCHAIN_API_KEY", ConfidenceLow},
		{FrameworkLangChain, SourceEnviron, "LANGCHAIN_TRACING", ConfidenceLow},

		// ── AutoGen ────────────────────────────────────────────────────
		{FrameworkAutoGen, SourceMaps, "autogen/", ConfidenceHigh},
		{FrameworkAutoGen, SourceMaps, "pyautogen", ConfidenceHigh},
		{FrameworkAutoGen, SourceCmdline, "autogen", ConfidenceMedium},

		// ── CrewAI ─────────────────────────────────────────────────────
		{FrameworkCrewAI, SourceMaps, "crewai/", ConfidenceHigh},
		{FrameworkCrewAI, SourceCmdline, "crewai", ConfidenceMedium},
		{FrameworkCrewAI, SourceEnviron, "CREWAI_", ConfidenceLow},

		// ── LlamaIndex ─────────────────────────────────────────────────
		{FrameworkLlamaIndex, SourceMaps, "llama_index/", ConfidenceHigh},
		{FrameworkLlamaIndex, SourceMaps, "llamaindex", ConfidenceHigh},
		{FrameworkLlamaIndex, SourceCmdline, "llamaindex", ConfidenceMedium},

		// ── OpenAI Agents SDK ──────────────────────────────────────────
		{FrameworkOpenAI, SourceMaps, "openai/agents", ConfidenceHigh},
		{FrameworkOpenAI, SourceMaps, "agents-sdk", ConfidenceHigh},
		{FrameworkOpenAI, SourceCmdline, "openai.agents", ConfidenceMedium},

		// ── Anthropic SDK / Claude Code ─────────────────────────────────
		{FrameworkAnthropic, SourceMaps, "anthropic/", ConfidenceHigh},
		{FrameworkAnthropic, SourceMaps, "claude/", ConfidenceHigh},
		{FrameworkAnthropic, SourceMaps, "claude_code", ConfidenceHigh},
		{FrameworkAnthropic, SourceCmdline, "claude", ConfidenceMedium},
		{FrameworkAnthropic, SourceCmdline, "anthropic", ConfidenceMedium},
		{FrameworkAnthropic, SourceEnviron, "ANTHROPIC_API_KEY", ConfidenceLow},
		{FrameworkAnthropic, SourceEnviron, "CLAUDE_", ConfidenceLow},

		// ── Phantex SDK (our own) ──────────────────────────────────────
		{FrameworkPhantexSDK, SourceMaps, "phantex_sdk", ConfidenceHigh},
		{FrameworkPhantexSDK, SourceMaps, "phantex/sdk", ConfidenceHigh},
		{FrameworkPhantexSDK, SourceEnviron, "PHANTEX_AGENT_ID", ConfidenceHigh},

		// ── Ollama (native LLM runner) ────────────────────────────────
		{FrameworkOllama, SourceCmdline, "ollama", ConfidenceHigh},
		{FrameworkOllama, SourceMaps, "ollama", ConfidenceHigh},
		{FrameworkOllama, SourceEnviron, "OLLAMA_HOST", ConfidenceMedium},

		// ── LM Studio (desktop LLM app) ─────────────────────────────
		{FrameworkLMStudio, SourceCmdline, "lm-studio", ConfidenceHigh},
		{FrameworkLMStudio, SourceCmdline, "lm studio", ConfidenceHigh},
		{FrameworkLMStudio, SourceMaps, "lm-studio", ConfidenceHigh},

		// ── llama.cpp / llama-server ──────────────────────────────
		{FrameworkLlamaCpp, SourceCmdline, "llama-server", ConfidenceHigh},
		{FrameworkLlamaCpp, SourceCmdline, "llama-cli", ConfidenceHigh},
		{FrameworkLlamaCpp, SourceCmdline, "llama.cpp", ConfidenceMedium},
		{FrameworkLlamaCpp, SourceCmdline, ".gguf", ConfidenceMedium},

		// ── LocalAI ───────────────────────────────────────────────
		{FrameworkLocalAI, SourceCmdline, "local-ai", ConfidenceHigh},
		{FrameworkLocalAI, SourceCmdline, "localai", ConfidenceHigh},

		// ── GPT4All ───────────────────────────────────────────────
		{FrameworkGPT4All, SourceCmdline, "gpt4all", ConfidenceHigh},
		{FrameworkGPT4All, SourceMaps, "gpt4all", ConfidenceHigh},

		// ── Jan AI ────────────────────────────────────────────────
		// NOTE: "jan" alone is too broad — matches libjansson, /home/jan/, etc.
		// Use Jan-specific patterns: @janhq npm packages, jan.ai paths
		{FrameworkJan, SourceMaps, "@janhq/", ConfidenceHigh},
		{FrameworkJan, SourceMaps, "jan.ai/", ConfidenceHigh},
		{FrameworkJan, SourceCmdline, "@janhq/", ConfidenceHigh},
		{FrameworkJan, SourceCmdline, "jan.ai", ConfidenceMedium},

		// ── KoboldCpp ─────────────────────────────────────────────
		{FrameworkKoboldCpp, SourceCmdline, "koboldcpp", ConfidenceHigh},

		// ── MCP (Model Context Protocol) ──────────────────────────
		// MCP servers launched via npx or as Python modules
		{FrameworkMCP, SourceCmdline, "@modelcontextprotocol/", ConfidenceHigh},
		{FrameworkMCP, SourceCmdline, "mcp-server", ConfidenceHigh},
		{FrameworkMCP, SourceCmdline, "mcp_server", ConfidenceHigh},
		{FrameworkMCP, SourceMaps, "mcp/server", ConfidenceHigh},
		{FrameworkMCP, SourceMaps, "mcp/client", ConfidenceHigh},
		{FrameworkMCP, SourceMaps, "modelcontextprotocol", ConfidenceHigh},
		{FrameworkMCP, SourceCmdline, "fastmcp", ConfidenceHigh},
		{FrameworkMCP, SourceMaps, "fastmcp", ConfidenceHigh},
		{FrameworkMCP, SourceEnviron, "MCP_SERVER_", ConfidenceMedium},

		// ── Site-packages fallback (Python) ──────────────────────────
		// CPython does not mmap .py files, so /proc/<pid>/maps won't
		// contain pure-Python package paths. These signatures check
		// the process's Python site-packages directory for installed
		// framework directories. Only checked for Python interpreters.
		{FrameworkLangChain, SourceSitePackages, "langchain_core", ConfidenceHigh},
		{FrameworkLangChain, SourceSitePackages, "langgraph", ConfidenceHigh},
		{FrameworkAutoGen, SourceSitePackages, "autogen", ConfidenceHigh},
		{FrameworkCrewAI, SourceSitePackages, "crewai", ConfidenceHigh},
		{FrameworkLlamaIndex, SourceSitePackages, "llama_index", ConfidenceHigh},
		{FrameworkOpenAI, SourceSitePackages, "openai", ConfidenceHigh},
		{FrameworkAnthropic, SourceSitePackages, "anthropic", ConfidenceHigh},
		{FrameworkPhantexSDK, SourceSitePackages, "phantex_sdk", ConfidenceHigh},
		{FrameworkMCP, SourceSitePackages, "mcp", ConfidenceHigh},
	}
}

// Match represents a successful signature match for a process.
type Match struct {
	Framework  Framework
	Confidence Confidence
	Source     SignatureSource
	Pattern    string // the pattern that matched
	Evidence   string // the actual line/value that triggered the match
}

// BestMatch returns the highest-confidence match from a set.
// If multiple frameworks have the same confidence, the first one wins.
func BestMatch(matches []Match) *Match {
	if len(matches) == 0 {
		return nil
	}
	best := &matches[0]
	for i := 1; i < len(matches); i++ {
		if matches[i].Confidence > best.Confidence {
			best = &matches[i]
		}
	}
	return best
}

// InterpreterNames are the process names (comm) that could host an AI agent.
// We only scan these — skipping obvious non-agent processes like bash, ls, etc.
var InterpreterNames = map[string]bool{
	"python":   true,
	"python3":  true,
	"python3.": false, // prefix match handled separately
	"node":     true,
	"deno":     true,
	"bun":      true,
	"java":     true, // for JVM-based agents
}

// NativeAIApps are standalone executables (not interpreters) that are always AI-related.
// If the process name matches, it's immediately classified without module scanning.
var NativeAIApps = map[string]Framework{
	"ollama":       FrameworkOllama,
	"lm-studio":    FrameworkLMStudio,
	"llama-server": FrameworkLlamaCpp,
	"llama-cli":    FrameworkLlamaCpp,
	"local-ai":     FrameworkLocalAI,
	"localai":      FrameworkLocalAI,
	"gpt4all":      FrameworkGPT4All,
	"chat":         FrameworkGPT4All, // GPT4All binary name on some installs
	"jan":          FrameworkJan,
	"koboldcpp":    FrameworkKoboldCpp,
	"mcp-server":   FrameworkMCP,
	"fastmcp":      FrameworkMCP,
}

// IsInterpreter checks if a process name (comm) could host an AI agent.
func IsInterpreter(comm string) bool {
	if InterpreterNames[comm] {
		return true
	}
	// Handle python3.X variants (python3.10, python3.12, etc.)
	if len(comm) >= 8 && comm[:7] == "python3" && comm[7] == '.' {
		return true
	}
	// Check native AI apps (ollama, llama-server, etc.)
	if _, ok := NativeAIApps[comm]; ok {
		return true
	}
	return false
}

// IsInterpreterExe checks whether a resolved /proc/<pid>/exe path points to an
// interpreter binary. This catches Python wrappers like gunicorn, uvicorn, celery,
// etc. whose /proc/<pid>/comm doesn't match "python3" but whose actual binary is
// a Python interpreter.
func IsInterpreterExe(exePath string) bool {
	if exePath == "" {
		return false
	}
	base := filepath.Base(exePath)
	return IsInterpreter(base)
}

// WatchlistSignatures generates signatures from user-configured binary patterns.
// This allows detection of Go/Rust/C++ AI agents that aren't interpreter-based.
// Each pattern is matched against /proc/<pid>/comm and /proc/<pid>/cmdline.
func WatchlistSignatures(patterns []string) []Signature {
	var sigs []Signature
	for _, p := range patterns {
		sigs = append(sigs,
			Signature{FrameworkWatchlist, SourceCmdline, p, ConfidenceHigh},
		)
	}
	return sigs
}
