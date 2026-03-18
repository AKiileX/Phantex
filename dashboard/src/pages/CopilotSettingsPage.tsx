// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Copilot AI Settings Page.
 *
 * Admin-only configuration for the Copilot LLM provider:
 *   - Provider selection (local / OpenAI / Anthropic / custom)
 *   - Endpoint URL, model, API key
 *   - Test Connection with auto-detection
 *   - Data privacy policy (local-only / allow cloud)
 *   - Security status overview
 *
 * @module pages/CopilotSettingsPage
 */

import { useCallback, useEffect, useState } from "react"
import {
  Bot,
  Check,
  Download,
  ExternalLink,
  Globe,
  Loader2,
  Lock,
  Monitor,
  RefreshCw,
  Save,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Unplug,
  Wifi,
  WifiOff,
  X,
  Zap,
  HelpCircle,
} from "lucide-react"
import { cn } from "@/lib/utils"
import {
  useCopilotConfig,
  useUpdateCopilotConfig,
  useTestCopilotConnection,
  type CopilotConfigUpdate,
  type TestConnectionResult,
} from "@/api/copilotSettings"
import { useCopilotHealth } from "@/api/copilot"

/* ── Provider presets ──────────────────────────────────────────────────────── */

const PROVIDERS = [
  {
    key: "local",
    label: "Local LLM",
    desc: "LM Studio, Ollama, vLLM, or any OpenAI-compatible server on your network",
    icon: Monitor,
    defaultUrl: "http://host.docker.internal:1234/v1",
    defaultModel: "mistral",
    needsKey: false,
  },
  {
    key: "openai",
    label: "OpenAI",
    desc: "GPT-4o, GPT-4o-mini — requires API key",
    icon: Zap,
    defaultUrl: "https://api.openai.com/v1",
    defaultModel: "gpt-4o-mini",
    needsKey: true,
  },
  {
    key: "anthropic",
    label: "Anthropic",
    desc: "Claude 3.5 Sonnet, Claude 3 Haiku — requires API key",
    icon: Bot,
    defaultUrl: "https://api.anthropic.com",
    defaultModel: "claude-3-5-sonnet-20241022",
    needsKey: true,
  },
  {
    key: "custom",
    label: "Custom Endpoint",
    desc: "Any OpenAI-compatible API (Azure, Groq, Together, self-hosted)",
    icon: Server,
    defaultUrl: "",
    defaultModel: "",
    needsKey: false,
  },
] as const

const SERVER_TYPE_LABELS: Record<string, string> = {
  lm_studio: "LM Studio",
  ollama: "Ollama",
  vllm: "vLLM",
  openai: "OpenAI",
  anthropic: "Anthropic",
  openai_compatible: "OpenAI-Compatible",
  text_generation_webui: "Text Generation WebUI",
  localai: "LocalAI",
  unknown: "Unknown",
}

/* ── Main page ─────────────────────────────────────────────────────────────── */

export default function CopilotSettingsPage() {
  const { data: config, isLoading } = useCopilotConfig()
  const { data: health } = useCopilotHealth(true)
  const updateMutation = useUpdateCopilotConfig()
  const testMutation = useTestCopilotConnection()

  // Form state
  const [provider, setProvider] = useState("local")
  const [showGuide, setShowGuide] = useState(false)
  const [baseUrl, setBaseUrl] = useState("http://host.docker.internal:1234/v1")
  const [model, setModel] = useState("mistral")
  const [apiKey, setApiKey] = useState("")
  const [apiKeyChanged, setApiKeyChanged] = useState(false)
  const [maxTokens, setMaxTokens] = useState(4096)
  const [temperature, setTemperature] = useState(0.3)
  const [dataPolicy, setDataPolicy] = useState("local_only")
  const [enabled, setEnabled] = useState(true)

  // Test results
  const [testResult, setTestResult] = useState<TestConnectionResult | null>(null)

  // Dirty tracking
  const [saved, setSaved] = useState(false)

  /* eslint-disable react-hooks/set-state-in-effect -- form hydration from API data */
  useEffect(() => {
    if (config) {
      setProvider(config.provider)
      setBaseUrl(config.base_url)
      setModel(config.model)
      setMaxTokens(config.max_tokens)
      setTemperature(config.temperature)
      setDataPolicy(config.data_policy)
      setEnabled(config.enabled)
      setApiKey("")
      setApiKeyChanged(false)
    }
  }, [config])
  /* eslint-enable react-hooks/set-state-in-effect */

  // Provider change => preset URL & model
  const handleProviderChange = useCallback(
    (key: string) => {
      setProvider(key)
      const preset = PROVIDERS.find((p) => p.key === key)
      if (preset) {
        if (preset.defaultUrl) setBaseUrl(preset.defaultUrl)
        if (preset.defaultModel) setModel(preset.defaultModel)
        // Cloud providers need allow_cloud data policy
        if (key === "openai" || key === "anthropic") {
          setDataPolicy("allow_cloud")
        }
      }
      setTestResult(null)
    },
    [],
  )

  // Save
  const handleSave = useCallback(async () => {
    const update: CopilotConfigUpdate = {
      provider,
      base_url: baseUrl,
      model,
      max_tokens: maxTokens,
      temperature,
      data_policy: dataPolicy,
      enabled,
    }
    if (apiKeyChanged && apiKey) {
      update.api_key = apiKey
    }
    try {
      await updateMutation.mutateAsync(update)
      setSaved(true)
      setApiKeyChanged(false)
      setTimeout(() => setSaved(false), 3000)
    } catch {
      // error shown by mutation state
    }
  }, [provider, baseUrl, model, apiKey, apiKeyChanged, maxTokens, temperature, dataPolicy, enabled, updateMutation])

  // Test connection
  const handleTest = useCallback(async () => {
    setTestResult(null)
    try {
      const result = await testMutation.mutateAsync({
        base_url: baseUrl,
        api_key: apiKeyChanged ? apiKey : undefined,
        model,
      })
      setTestResult(result)
      // If models detected and our model not in list, suggest first one
      if (result.available_models.length > 0 && !result.available_models.includes(model)) {
        // Don't auto-change, just show the available list
      }
    } catch {
      // error handled by mutation state
    }
  }, [baseUrl, apiKey, apiKeyChanged, model, testMutation])

  // Current provider preset
  const currentPreset = PROVIDERS.find((p) => p.key === provider) ?? PROVIDERS[0]

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="h-6 w-6 animate-spin text-primary" />
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 border border-emerald-500/30">
            <Sparkles size={20} className="text-emerald-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-foreground">Copilot AI Configuration</h1>
            <p className="text-sm text-muted-foreground">
              Configure the LLM provider for Phantex Copilot — investigation, triage, and rule generation.
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowGuide(!showGuide)}
          className="flex items-center gap-1.5 rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/5 transition-colors cursor-pointer"
        >
          <HelpCircle size={14} />
          {showGuide ? "Hide Guide" : "How does this work?"}
        </button>
      </div>

      {showGuide && (
        <div className="space-y-4">
          <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
              <Sparkles size={16} className="text-emerald-400" />
              What is Copilot AI?
            </h3>
            <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
              <strong className="text-foreground">Phantex Copilot</strong> is an AI-powered investigation assistant that helps you triage alerts, analyze events, generate detection rules, and query your security data using natural language. It runs entirely within your infrastructure — no data leaves your network.
            </p>
          </div>
          <div className="rounded-xl border border-primary/20 bg-primary/[0.03] p-5">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
              <Server size={16} className="text-primary" />
              Configuration
            </h3>
            <div className="mt-2 space-y-1.5 text-xs text-muted-foreground">
              <p><strong className="text-foreground">Provider:</strong> Choose between local LLM (LM Studio, Ollama) or cloud (OpenAI, Anthropic). Local is recommended for data privacy.</p>
              <p><strong className="text-foreground">Model:</strong> Select the model to use. Larger models give better answers but are slower.</p>
              <p><strong className="text-foreground">Test Connection:</strong> Verify the LLM endpoint is reachable before saving.</p>
              <p><strong className="text-foreground">Data Policy:</strong> &quot;Private / Local&quot; means all inference stays on-prem. &quot;Public / Cloud&quot; means requests go to an external API.</p>
            </div>
          </div>
        </div>
      )}

      {/* Security Status Bar */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <StatusCard
          icon={health?.copilot_status === "healthy" ? Wifi : WifiOff}
          label="LLM Status"
          value={health?.copilot_status ?? "unknown"}
          variant={health?.copilot_status === "healthy" ? "success" : health?.copilot_status === "degraded" ? "warning" : "danger"}
        />
        <StatusCard
          icon={config?.endpoint_type === "private" ? Lock : Globe}
          label="Endpoint"
          value={config?.endpoint_type === "private" ? "Private / Local" : "Public / Cloud"}
          variant={config?.endpoint_type === "private" ? "success" : "warning"}
        />
        <StatusCard
          icon={ShieldCheck}
          label="Firewall"
          value="Active"
          variant="success"
        />
        <StatusCard
          icon={config?.data_policy === "local_only" ? ShieldCheck : ShieldAlert}
          label="Data Policy"
          value={config?.data_policy === "local_only" ? "Local Only" : "Cloud Allowed"}
          variant={config?.data_policy === "local_only" ? "success" : "warning"}
        />
      </div>

      {/* Provider Selection */}
      <Card title="LLM Provider" icon={Server}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {PROVIDERS.map((p) => (
            <button
              key={p.key}
              onClick={() => handleProviderChange(p.key)}
              className={cn(
                "flex items-start gap-3 rounded-xl border p-4 text-left transition-all",
                provider === p.key
                  ? "border-emerald-500/50 bg-emerald-500/[0.05] ring-1 ring-emerald-500/20"
                  : "border-white/10 bg-white/[0.02] hover:bg-white/[0.04] hover:border-white/20",
              )}
            >
              <div
                className={cn(
                  "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border",
                  provider === p.key
                    ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                    : "bg-white/5 border-white/10 text-muted-foreground",
                )}
              >
                <p.icon size={18} />
              </div>
              <div>
                <p className="text-sm font-medium text-foreground">{p.label}</p>
                <p className="mt-0.5 text-xs text-muted-foreground">{p.desc}</p>
              </div>
              {provider === p.key && (
                <Check size={16} className="ml-auto shrink-0 text-emerald-400" />
              )}
            </button>
          ))}
        </div>
      </Card>

      {/* Getting Started — only shown for local provider */}
      {provider === "local" && (
        <Card title="Getting Started — Download a Local LLM" icon={Download}>
          <div className="space-y-4">
            <p className="text-xs text-muted-foreground">
              To use Copilot with a local LLM, download and run one of these servers on your machine.
              Your data never leaves your network.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <QuickStartCard
                name="LM Studio"
                desc="One-click model download, GUI, OpenAI-compatible API. Best for beginners."
                url="https://lmstudio.ai"
                port="1234"
                recommended
                steps={[
                  "Download & install LM Studio",
                  "Browse models → search \"Mistral\" or \"Llama\"",
                  "Click Download on a model (7B recommended)",
                  "Go to Local Server tab → Start Server",
                  "Come back here and click Test",
                ]}
              />
              <QuickStartCard
                name="Ollama"
                desc="CLI-first, lightweight, great for servers and automation."
                url="https://ollama.com"
                port="11434"
                steps={[
                  "Install: curl -fsSL https://ollama.com/install.sh | sh",
                  "Pull a model: ollama pull mistral",
                  "It auto-serves on port 11434",
                  "Change endpoint URL above to :11434/v1",
                  "Click Test to verify",
                ]}
              />
              <QuickStartCard
                name="vLLM"
                desc="Production-grade, GPU-optimized, best for high-throughput."
                url="https://docs.vllm.ai"
                port="8000"
                steps={[
                  "pip install vllm",
                  "vllm serve mistralai/Mistral-7B-Instruct-v0.3",
                  "Serves on port 8000 by default",
                  "Change endpoint URL above to :8000/v1",
                  "Click Test to verify",
                ]}
              />
            </div>

            <div className="rounded-lg border border-blue-500/20 bg-blue-500/[0.05] p-3 text-xs text-blue-400/80">
              <p className="font-medium text-blue-400">Recommended models for security analysis:</p>
              <ul className="mt-1 space-y-0.5 ml-3 list-disc">
                <li><span className="text-foreground/70">Mistral 7B</span> — Fast, great for triage & rules (4GB RAM)</li>
                <li><span className="text-foreground/70">Llama 3.1 8B</span> — Strong reasoning, good for investigation (5GB RAM)</li>
                <li><span className="text-foreground/70">Qwen 2.5 7B</span> — Excellent code understanding for rule generation (4GB RAM)</li>
                <li><span className="text-foreground/70">Mixtral 8x7B</span> — Best quality, needs more RAM (26GB RAM)</li>
              </ul>
            </div>

            {/* Already downloaded a raw model file? */}
            <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.05] p-3 text-xs">
              <p className="font-medium text-amber-400">Already downloaded a .gguf file from HuggingFace?</p>
              <p className="mt-1 text-muted-foreground">
                Raw model files can't serve an API on their own — you need a server to load them.
                Here's how to use your downloaded file:
              </p>
              <ul className="mt-2 space-y-1.5 text-muted-foreground">
                <li className="flex gap-2">
                  <span className="shrink-0 font-bold text-foreground/50">LM Studio:</span>
                  <span>Drop the .gguf file into <code className="rounded bg-white/[0.06] px-1 text-foreground/60">~/.cache/lm-studio/models/</code> → it appears in the model list → load it → start server</span>
                </li>
                <li className="flex gap-2">
                  <span className="shrink-0 font-bold text-foreground/50">Ollama:</span>
                  <span>Create a Modelfile: <code className="rounded bg-white/[0.06] px-1 text-foreground/60">FROM ./your-model.gguf</code> → run <code className="rounded bg-white/[0.06] px-1 text-foreground/60">ollama create mymodel -f Modelfile</code> → <code className="rounded bg-white/[0.06] px-1 text-foreground/60">ollama serve</code></span>
                </li>
                <li className="flex gap-2">
                  <span className="shrink-0 font-bold text-foreground/50">llama.cpp:</span>
                  <span><code className="rounded bg-white/[0.06] px-1 text-foreground/60">./llama-server -m your-model.gguf --port 8080</code> → set endpoint to <code className="rounded bg-white/[0.06] px-1 text-foreground/60">:8080/v1</code></span>
                </li>
              </ul>
              <p className="mt-2 text-muted-foreground/70">
                Tip: GGUF is the most universal format. If you downloaded safetensors or PyTorch files, 
                use LM Studio (auto-converts) or convert with <code className="rounded bg-white/[0.06] px-1 text-foreground/60">llama.cpp/convert_hf_to_gguf.py</code>.
              </p>
            </div>
          </div>
        </Card>
      )}

      {/* Connection Settings */}
      <Card title="Connection Settings" icon={Unplug}>
        <div className="space-y-4">
          {/* Endpoint URL */}
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
              Endpoint URL
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={baseUrl}
                onChange={(e) => { setBaseUrl(e.target.value); setTestResult(null) }}
                placeholder="http://host.docker.internal:1234/v1"
                className="flex-1 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/20"
              />
              <button
                onClick={handleTest}
                disabled={!baseUrl || testMutation.isPending}
                className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs font-medium text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-40 transition-colors"
              >
                {testMutation.isPending ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <RefreshCw size={14} />
                )}
                Test
              </button>
            </div>
            {provider === "local" && (
              <p className="mt-1 text-[11px] text-muted-foreground/60">
                Default LM Studio port: 1234 · Ollama: 11434 · vLLM: 8000
              </p>
            )}
          </div>

          {/* Test results */}
          {testResult && (
            <div
              className={cn(
                "rounded-lg border p-3 text-xs",
                testResult.reachable
                  ? "border-emerald-500/30 bg-emerald-500/[0.05]"
                  : "border-red-500/30 bg-red-500/[0.05]",
              )}
            >
              <div className="flex items-center gap-2">
                {testResult.reachable ? (
                  <Check size={14} className="text-emerald-400" />
                ) : (
                  <X size={14} className="text-red-400" />
                )}
                <span className={testResult.reachable ? "text-emerald-400 font-medium" : "text-red-400 font-medium"}>
                  {testResult.reachable ? "Connected" : "Connection Failed"}
                </span>
                {testResult.reachable && (
                  <span className="text-muted-foreground">
                    · {SERVER_TYPE_LABELS[testResult.detected_server] ?? testResult.detected_server}
                    · {testResult.latency_ms}ms
                    · {testResult.endpoint_type === "private" ? "🔒 Private" : "🌐 Public"}
                  </span>
                )}
              </div>
              {testResult.error && (
                <p className="mt-1 text-red-400/80">{testResult.error}</p>
              )}
              {testResult.available_models.length > 0 && (
                <div className="mt-2">
                  <p className="text-muted-foreground mb-1">Available models ({testResult.available_models.length}):</p>
                  <div className="flex flex-wrap gap-1">
                    {testResult.available_models.slice(0, 20).map((m) => (
                      <button
                        key={m}
                        onClick={() => setModel(m)}
                        className={cn(
                          "rounded-full border px-2 py-0.5 text-[10px] transition-colors",
                          m === model
                            ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400"
                            : "border-white/10 bg-white/[0.03] text-muted-foreground hover:text-foreground hover:border-white/20",
                        )}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {testMutation.isError && !testResult && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/[0.05] p-3 text-xs text-red-400">
              Failed to test connection: {testMutation.error.message}
            </div>
          )}

          {/* Model name */}
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
              Model
            </label>
            <input
              type="text"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="mistral"
              className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/20"
            />
            <p className="mt-1 text-[11px] text-muted-foreground/60">
              The model loaded in your LLM server. Click a model from Test results to select it.
            </p>
          </div>

          {/* API Key */}
          {(currentPreset.needsKey || provider === "custom") && (
            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
                API Key
              </label>
              <div className="relative">
                <input
                  type="password"
                  value={apiKeyChanged ? apiKey : ""}
                  onChange={(e) => {
                    setApiKey(e.target.value)
                    setApiKeyChanged(true)
                  }}
                  placeholder={config?.has_api_key ? `Current: ${config.api_key_masked}` : "sk-..."}
                  className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 pr-10 text-sm text-foreground placeholder:text-muted-foreground/40 focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/20"
                />
                <Lock size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground/40" />
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground/60">
                Encrypted at rest. Never sent back to the browser. Leave blank to keep current key.
              </p>
            </div>
          )}

          {/* Max tokens + Temperature */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
                Max Tokens
              </label>
              <input
                type="number"
                value={maxTokens}
                onChange={(e) => setMaxTokens(Number(e.target.value))}
                min={256}
                max={32768}
                className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-foreground focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/20"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
                Temperature
              </label>
              <input
                type="number"
                value={temperature}
                onChange={(e) => setTemperature(Number(e.target.value))}
                min={0}
                max={2}
                step={0.1}
                className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-foreground focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/20"
              />
              <p className="mt-1 text-[11px] text-muted-foreground/60">
                Lower = more deterministic (0.3 recommended for security analysis)
              </p>
            </div>
          </div>
        </div>
      </Card>

      {/* Data Privacy Policy */}
      <Card title="Data Privacy Policy" icon={Shield}>
        <div className="space-y-4">
          <div className="flex items-start gap-4">
            <button
              onClick={() => setDataPolicy("local_only")}
              className={cn(
                "flex-1 rounded-xl border p-4 text-left transition-all",
                dataPolicy === "local_only"
                  ? "border-emerald-500/50 bg-emerald-500/[0.05] ring-1 ring-emerald-500/20"
                  : "border-white/10 bg-white/[0.02] hover:bg-white/[0.04]",
              )}
            >
              <div className="flex items-center gap-2">
                <ShieldCheck size={16} className={dataPolicy === "local_only" ? "text-emerald-400" : "text-muted-foreground"} />
                <span className="text-sm font-medium text-foreground">Local Only (Default)</span>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Zero data leaves your network. Only private/localhost endpoints are allowed.
                Cloud API endpoints will be blocked.
              </p>
            </button>

            <button
              onClick={() => setDataPolicy("allow_cloud")}
              className={cn(
                "flex-1 rounded-xl border p-4 text-left transition-all",
                dataPolicy === "allow_cloud"
                  ? "border-amber-500/50 bg-amber-500/[0.05] ring-1 ring-amber-500/20"
                  : "border-white/10 bg-white/[0.02] hover:bg-white/[0.04]",
              )}
            >
              <div className="flex items-center gap-2">
                <Globe size={16} className={dataPolicy === "allow_cloud" ? "text-amber-400" : "text-muted-foreground"} />
                <span className="text-sm font-medium text-foreground">Allow Cloud</span>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Permits sending data to external LLM APIs (OpenAI, Anthropic, etc.).
                All data still passes through the content firewall.
              </p>
            </button>
          </div>

          {dataPolicy === "allow_cloud" && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/[0.05] p-3 text-xs text-amber-400">
              <div className="flex items-center gap-1.5 font-medium">
                <ShieldAlert size={14} />
                Cloud mode active
              </div>
              <p className="mt-1 text-amber-400/70">
                Copilot queries will be sent to external servers. The content firewall still scrubs
                internal IPs, container names, credentials, and PII from all LLM interactions.
                Ensure this complies with your organization's data governance policies.
              </p>
            </div>
          )}
        </div>
      </Card>

      {/* Security Overview */}
      <Card title="Security Layers" icon={ShieldCheck}>
        <div className="space-y-2">
          <SecurityRow
            label="Content Firewall (U0)"
            desc="Scans input for prompt injection, scrubs output for secrets/PII/internal data"
            status="active"
          />
          <SecurityRow
            label="RBAC Gate"
            desc="Copilot requires copilot.use permission — admin and analyst roles only"
            status="active"
          />
          <SecurityRow
            label="Rate Limiter"
            desc="10 requests/min for chat, 5/min for triage — prevents abuse"
            status="active"
          />
          <SecurityRow
            label="Tenant Isolation (RLS)"
            desc="All data queries are scoped to the authenticated tenant — no cross-tenant access"
            status="active"
          />
          <SecurityRow
            label="API Key Encryption"
            desc="Keys encrypted at rest with Fernet (AES-128-CBC) — never returned to the browser"
            status="active"
          />
          <SecurityRow
            label="Audit Logging"
            desc="Every copilot interaction logged with user, tenant, provider, and token usage"
            status="active"
          />
          <SecurityRow
            label="Stateless LLM"
            desc="LLM has zero persistent Phantex knowledge — context injected per-request, scrubbed after"
            status="active"
          />
        </div>
      </Card>

      {/* Save Bar */}
      <div className="sticky bottom-0 flex items-center justify-between rounded-xl border border-white/10 bg-[#0a0a0e]/95 backdrop-blur-xl px-4 py-3 shadow-2xl">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {config?.updated_at && (
            <span>Last saved: {new Date(config.updated_at).toLocaleString()}</span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {/* Enabled toggle */}
          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-white/20 bg-white/5 text-emerald-500 focus:ring-emerald-500/20"
            />
            Copilot enabled
          </label>

          {updateMutation.isError && (
            <span className="text-xs text-red-400">
              {updateMutation.error.message}
            </span>
          )}

          <button
            onClick={handleSave}
            disabled={updateMutation.isPending}
            className={cn(
              "flex items-center gap-1.5 rounded-lg px-5 py-2 text-sm font-medium text-white transition-all",
              saved
                ? "bg-emerald-600"
                : "bg-primary hover:bg-primary/90",
              updateMutation.isPending && "opacity-60 cursor-not-allowed",
            )}
          >
            {updateMutation.isPending ? (
              <Loader2 size={14} className="animate-spin" />
            ) : saved ? (
              <Check size={14} />
            ) : (
              <Save size={14} />
            )}
            {saved ? "Saved" : "Save Configuration"}
          </button>
        </div>
      </div>
    </div>
  )
}

/* ── Sub-components ────────────────────────────────────────────────────────── */

function Card({
  title,
  icon: Icon,
  children,
}: {
  title: string
  icon: React.ComponentType<{ size?: number; className?: string }>
  children: React.ReactNode
}) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
      <div className="flex items-center gap-2 border-b border-white/10 px-5 py-3">
        <Icon size={16} className="text-muted-foreground" />
        <h2 className="text-sm font-semibold text-foreground">{title}</h2>
      </div>
      <div className="p-5">{children}</div>
    </div>
  )
}

function StatusCard({
  icon: Icon,
  label,
  value,
  variant,
}: {
  icon: React.ComponentType<{ size?: number; className?: string }>
  label: string
  value: string
  variant: "success" | "warning" | "danger"
}) {
  const colors = {
    success: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    warning: "text-amber-400 bg-amber-500/10 border-amber-500/20",
    danger: "text-red-400 bg-red-500/10 border-red-500/20",
  }
  return (
    <div className={cn("rounded-xl border p-3", colors[variant])}>
      <div className="flex items-center gap-2">
        <Icon size={14} />
        <span className="text-xs font-medium">{value}</span>
      </div>
      <p className="mt-0.5 text-[10px] opacity-60">{label}</p>
    </div>
  )
}

function SecurityRow({
  label,
  desc,
  status,
}: {
  label: string
  desc: string
  status: "active" | "inactive"
}) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.01] px-4 py-2.5">
      <div
        className={cn(
          "h-2 w-2 rounded-full",
          status === "active"
            ? "bg-emerald-400 shadow-[0_0_6px_rgb(52,211,153)]"
            : "bg-red-400",
        )}
      />
      <div className="flex-1">
        <p className="text-xs font-medium text-foreground">{label}</p>
        <p className="text-[11px] text-muted-foreground">{desc}</p>
      </div>
      <span
        className={cn(
          "rounded-full border px-2 py-0.5 text-[10px] font-medium",
          status === "active"
            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
            : "border-red-500/30 bg-red-500/10 text-red-400",
        )}
      >
        {status}
      </span>
    </div>
  )
}

function QuickStartCard({
  name,
  desc,
  url,
  port,
  steps,
  recommended,
}: {
  name: string
  desc: string
  url: string
  port: string
  steps: string[]
  recommended?: boolean
}) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div
      className={cn(
        "rounded-xl border p-4 transition-all",
        recommended
          ? "border-emerald-500/30 bg-emerald-500/[0.03]"
          : "border-white/10 bg-white/[0.02]",
      )}
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-1.5">
            <p className="text-sm font-medium text-foreground">{name}</p>
            {recommended && (
              <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[9px] font-medium text-emerald-400">
                RECOMMENDED
              </span>
            )}
          </div>
          <p className="mt-0.5 text-[11px] text-muted-foreground">{desc}</p>
        </div>
      </div>

      <div className="mt-3 flex items-center gap-2">
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1 rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 text-[10px] font-medium text-foreground/80 hover:bg-white/[0.08] transition-colors"
        >
          <ExternalLink size={10} />
          {url.replace("https://", "")}
        </a>
        <span className="rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 text-[10px] text-muted-foreground">
          Port {port}
        </span>
      </div>

      <button
        onClick={() => setExpanded(!expanded)}
        className="mt-2 text-[10px] font-medium text-primary/70 hover:text-primary transition-colors"
      >
        {expanded ? "Hide steps ▴" : "Show setup steps ▾"}
      </button>

      {expanded && (
        <ol className="mt-2 space-y-1 text-[11px] text-muted-foreground">
          {steps.map((step, i) => (
            <li key={i} className="flex gap-2">
              <span className="shrink-0 flex h-4 w-4 items-center justify-center rounded-full bg-white/[0.06] text-[9px] font-bold text-foreground/50">
                {i + 1}
              </span>
              <span className="font-mono text-foreground/60">{step}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}
