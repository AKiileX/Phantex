using System.Security.Cryptography;

namespace Phantex.SDK;

/// <summary>
/// Trace context management using AsyncLocal for correct async/await propagation.
/// </summary>
public static class PhantexContext
{
    private static readonly AsyncLocal<string> _traceId = new();
    private static readonly AsyncLocal<string> _spanId = new();
    private static readonly AsyncLocal<string> _parentSpanId = new();
    private static readonly AsyncLocal<string> _agentPaid = new();
    private static readonly AsyncLocal<string> _framework = new();

    public static string NewTraceId() => Guid.NewGuid().ToString("N");

    public static string NewSpanId() => Guid.NewGuid().ToString("N")[..16];

    public static string TraceId
    {
        get
        {
            var v = _traceId.Value;
            if (string.IsNullOrEmpty(v))
            {
                v = NewTraceId();
                _traceId.Value = v;
            }
            return v;
        }
        set => _traceId.Value = value;
    }

    public static string SpanId
    {
        get => _spanId.Value ?? "";
        set => _spanId.Value = value;
    }

    public static string ParentSpanId
    {
        get => _parentSpanId.Value ?? "";
        set => _parentSpanId.Value = value;
    }

    public static string AgentPaid
    {
        get
        {
            var v = _agentPaid.Value;
            if (string.IsNullOrEmpty(v))
                v = Environment.GetEnvironmentVariable("PHANTEX_AGENT_ID") ?? "";
            return v;
        }
        set => _agentPaid.Value = value;
    }

    public static string Framework
    {
        get => _framework.Value ?? "";
        set => _framework.Value = value;
    }

    public static SpanContext Current => new(
        TraceId, SpanId, ParentSpanId, AgentPaid, Framework
    );
}

/// <summary>
/// Snapshot of the current tracing context.
/// </summary>
public sealed record SpanContext(
    string TraceId,
    string SpanId,
    string ParentSpanId,
    string AgentPaid,
    string Framework
);
