using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Phantex.SDK;

public enum EventType
{
    Unspecified = 0,
    ProcessExec = 1, ProcessExit = 2,
    FileOpen = 10, FileWrite = 11, FileRead = 12,
    NetworkConnect = 20, NetworkAccept = 21, NetworkDns = 22,
    MemoryMmap = 30,
    AgentDiscovered = 40, AgentTerminated = 41,
    ToolCall = 50, ToolResponse = 51,
    AlertFired = 60,
}

public enum Severity
{
    Unspecified = 0, Info = 1, Low = 2, Medium = 3, High = 4, Critical = 5,
}

/// <summary>
/// A captured tool/function call event.
/// </summary>
public sealed class ToolCallEvent : IPhantexEvent
{
    [JsonPropertyName("event_id")] public string EventId { get; init; } = Guid.NewGuid().ToString("N");
    [JsonPropertyName("event_type")] public int EventTypeCode { get; init; } = (int)EventType.ToolCall;
    [JsonPropertyName("timestamp_ns")] public long TimestampNs { get; init; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1_000_000;
    [JsonPropertyName("tenant_id")] public string TenantId { get; set; } = "";
    [JsonPropertyName("agent_paid")] public string AgentPaid { get; set; } = "";
    [JsonPropertyName("pid")] public int Pid { get; set; }
    [JsonPropertyName("tool_name")] public string ToolName { get; set; } = "";
    [JsonPropertyName("tool_input")] public string ToolInput { get; set; } = "";
    [JsonPropertyName("protocol")] public string Protocol { get; set; } = "";
    [JsonPropertyName("framework")] public string Framework { get; set; } = "";
    [JsonPropertyName("model_name")] public string ModelName { get; set; } = "";
    [JsonPropertyName("prompt_hash")] public string PromptHash { get; set; } = "";
    [JsonPropertyName("input_tokens")] public int InputTokens { get; set; }
    [JsonPropertyName("output_tokens")] public int OutputTokens { get; set; }
    [JsonPropertyName("trace_id")] public string TraceId { get; set; } = "";
    [JsonPropertyName("span_id")] public string SpanId { get; set; } = "";
    [JsonPropertyName("parent_span_id")] public string ParentSpanId { get; set; } = "";
    [JsonPropertyName("severity")] public int SeverityCode { get; set; } = (int)Severity.Info;

    public byte[] ToJson() =>
        JsonSerializer.SerializeToUtf8Bytes(this, PhantexJsonContext.Default.ToolCallEvent);
}

/// <summary>
/// A captured tool/function response event.
/// </summary>
public sealed class ToolResponseEvent : IPhantexEvent
{
    [JsonPropertyName("event_id")] public string EventId { get; init; } = Guid.NewGuid().ToString("N");
    [JsonPropertyName("event_type")] public int EventTypeCode { get; init; } = (int)EventType.ToolResponse;
    [JsonPropertyName("timestamp_ns")] public long TimestampNs { get; init; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1_000_000;
    [JsonPropertyName("tenant_id")] public string TenantId { get; set; } = "";
    [JsonPropertyName("agent_paid")] public string AgentPaid { get; set; } = "";
    [JsonPropertyName("pid")] public int Pid { get; set; }
    [JsonPropertyName("tool_name")] public string ToolName { get; set; } = "";
    [JsonPropertyName("protocol")] public string Protocol { get; set; } = "";
    [JsonPropertyName("framework")] public string Framework { get; set; } = "";
    [JsonPropertyName("success")] public bool Success { get; set; } = true;
    [JsonPropertyName("duration_ns")] public long DurationNs { get; set; }
    [JsonPropertyName("output_size")] public int OutputSize { get; set; }
    [JsonPropertyName("error_message")] public string ErrorMessage { get; set; } = "";
    [JsonPropertyName("model_name")] public string ModelName { get; set; } = "";
    [JsonPropertyName("input_tokens")] public int InputTokens { get; set; }
    [JsonPropertyName("output_tokens")] public int OutputTokens { get; set; }
    [JsonPropertyName("trace_id")] public string TraceId { get; set; } = "";
    [JsonPropertyName("span_id")] public string SpanId { get; set; } = "";
    [JsonPropertyName("parent_span_id")] public string ParentSpanId { get; set; } = "";
    [JsonPropertyName("severity")] public int SeverityCode { get; set; } = (int)Severity.Info;

    public byte[] ToJson() =>
        JsonSerializer.SerializeToUtf8Bytes(this, PhantexJsonContext.Default.ToolResponseEvent);
}

public interface IPhantexEvent
{
    byte[] ToJson();
}

public static class EventHelpers
{
    public static string HashPrompt(string prompt)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(prompt));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string SafeSerialize(object? value, int maxChars = 4096)
    {
        try
        {
            var json = JsonSerializer.Serialize(value);
            if (json.Length <= maxChars) return json;
            // Avoid splitting a surrogate pair
            var cut = maxChars - 3;
            if (cut > 0 && char.IsHighSurrogate(json[cut - 1]))
                cut--;
            return string.Concat(json.AsSpan(0, cut), "...");
        }
        catch
        {
            return "<unserializable>";
        }
    }
}

[JsonSerializable(typeof(ToolCallEvent))]
[JsonSerializable(typeof(ToolResponseEvent))]
internal partial class PhantexJsonContext : JsonSerializerContext { }
