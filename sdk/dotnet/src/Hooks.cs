using System.Diagnostics;
using System.Net.Http;

namespace Phantex.SDK;

/// <summary>
/// Hook interface — all framework integrations implement this.
/// </summary>
public interface IPhantexHook
{
    string Name { get; }
    bool Install();
    void Uninstall();
}

/// <summary>
/// Hook registry — discovers and creates hooks based on configuration.
/// </summary>
public static class HookRegistry
{
    private static readonly Dictionary<string, Func<ITransport, PhantexConfig, IPhantexHook>> _registry = new()
    {
        ["semantickernel"] = (t, c) => new SemanticKernelHook(t, c),
        ["http"] = (t, c) => new HttpClientHook(t, c),
    };

    public static IEnumerable<IPhantexHook> CreateAll(ITransport transport, PhantexConfig config)
    {
        var hooksConfig = config.Hooks.ToLowerInvariant().Trim();
        IEnumerable<string> names = hooksConfig switch
        {
            "none" => [],
            "auto" => _registry.Keys,
            _ => hooksConfig.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
        };

        foreach (var name in names)
        {
            if (_registry.TryGetValue(name, out var factory))
                yield return factory(transport, config);
        }
    }
}

/// <summary>
/// Hook for Microsoft Semantic Kernel — intercepts kernel function invocations.
/// </summary>
public sealed class SemanticKernelHook : IPhantexHook
{
    private readonly ITransport _transport;
    private readonly PhantexConfig _config;
    private bool _installed;

    public SemanticKernelHook(ITransport transport, PhantexConfig config)
    {
        _transport = transport;
        _config = config;
    }

    public string Name => "semantickernel";

    public bool Install()
    {
        // Semantic Kernel uses a filter/middleware pattern.
        // Users register this hook as an IFunctionInvocationFilter on their Kernel.
        // The Install() here just validates that the hook is ready.
        _installed = true;
        return true;
    }

    public void Uninstall() => _installed = false;

    /// <summary>
    /// Call this from a Semantic Kernel IFunctionInvocationFilter to capture function invocations.
    /// </summary>
    public async Task OnFunctionInvocationAsync(
        string functionName,
        string pluginName,
        string modelName,
        Func<Task> next)
    {
        var sc = PhantexContext.Current;
        var spanId = PhantexContext.NewSpanId();

        var callEvt = new ToolCallEvent
        {
            TenantId = _config.TenantId,
            AgentPaid = sc.AgentPaid,
            ToolName = $"{pluginName}.{functionName}",
            Protocol = "semantic_kernel",
            Framework = "SemanticKernel",
            ModelName = modelName,
            TraceId = sc.TraceId,
            SpanId = spanId,
            ParentSpanId = sc.SpanId,
        };
        await _transport.SendAsync(callEvt);

        var sw = Stopwatch.StartNew();
        string? error = null;
        bool success = true;

        try
        {
            await next();
        }
        catch (Exception ex)
        {
            success = false;
            error = ex.Message;
            throw;
        }
        finally
        {
            sw.Stop();
            var respEvt = new ToolResponseEvent
            {
                TenantId = _config.TenantId,
                AgentPaid = sc.AgentPaid,
                ToolName = $"{pluginName}.{functionName}",
                Protocol = "semantic_kernel",
                Framework = "SemanticKernel",
                ModelName = modelName,
                Success = success,
                DurationNs = sw.Elapsed.Ticks * 100, // ticks are 100ns
                ErrorMessage = error ?? "",
                TraceId = sc.TraceId,
                SpanId = spanId,
            };
            await _transport.SendAsync(respEvt);
        }
    }
}

/// <summary>
/// Hook for generic HttpClient — intercepts outgoing HTTP requests to AI API endpoints.
/// Uses a DelegatingHandler that can be added to HttpClient via IHttpClientFactory or directly.
/// </summary>
public sealed class HttpClientHook : IPhantexHook
{
    private readonly ITransport _transport;
    private readonly PhantexConfig _config;
    private bool _installed;

    public HttpClientHook(ITransport transport, PhantexConfig config)
    {
        _transport = transport;
        _config = config;
    }

    public string Name => "http";
    public bool Install() { _installed = true; return true; }
    public void Uninstall() => _installed = false;

    /// <summary>
    /// Creates a DelegatingHandler that captures AI API calls.
    /// Use with HttpClient or IHttpClientFactory.
    /// </summary>
    public DelegatingHandler CreateHandler(HttpMessageHandler? inner = null)
    {
        return new PhantexDelegatingHandler(_transport, _config)
        {
            InnerHandler = inner ?? new SocketsHttpHandler()
        };
    }
}

internal sealed class PhantexDelegatingHandler : DelegatingHandler
{
    private static readonly HashSet<string> AiHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.cohere.ai",
        "api.mistral.ai",
    };

    private readonly ITransport _transport;
    private readonly PhantexConfig _config;

    public PhantexDelegatingHandler(ITransport transport, PhantexConfig config)
    {
        _transport = transport;
        _config = config;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var host = request.RequestUri?.Host ?? "";
        if (!AiHosts.Contains(host))
            return await base.SendAsync(request, ct);

        var sc = PhantexContext.Current;
        var spanId = PhantexContext.NewSpanId();

        var callEvt = new ToolCallEvent
        {
            TenantId = _config.TenantId,
            AgentPaid = sc.AgentPaid,
            ToolName = request.RequestUri?.AbsolutePath ?? "",
            Protocol = "http",
            Framework = "HttpClient",
            TraceId = sc.TraceId,
            SpanId = spanId,
            ParentSpanId = sc.SpanId,
        };
        await _transport.SendAsync(callEvt, ct);

        var sw = Stopwatch.StartNew();
        HttpResponseMessage? response = null;
        string? error = null;
        bool success = true;

        try
        {
            response = await base.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                success = false;
                error = response.ReasonPhrase;
            }
            return response;
        }
        catch (Exception ex)
        {
            success = false;
            error = ex.Message;
            throw;
        }
        finally
        {
            sw.Stop();
            var respEvt = new ToolResponseEvent
            {
                TenantId = _config.TenantId,
                AgentPaid = sc.AgentPaid,
                ToolName = request.RequestUri?.AbsolutePath ?? "",
                Protocol = "http",
                Framework = "HttpClient",
                Success = success,
                DurationNs = sw.Elapsed.Ticks * 100,
                OutputSize = (int)(response?.Content.Headers.ContentLength ?? 0),
                ErrorMessage = error ?? "",
                TraceId = sc.TraceId,
                SpanId = spanId,
            };
            await _transport.SendAsync(respEvt, ct);
        }
    }
}
