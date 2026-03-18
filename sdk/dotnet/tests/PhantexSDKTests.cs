using System.Text;
using System.Text.Json;
using Xunit;

namespace Phantex.SDK.Tests;

public class ConfigTests
{
    [Fact]
    public void FromEnv_ReadsEnvironmentVariables()
    {
        Environment.SetEnvironmentVariable("PHANTEX_TOKEN", "test-token");
        Environment.SetEnvironmentVariable("PHANTEX_TENANT_ID", "tenant-123");
        Environment.SetEnvironmentVariable("PHANTEX_AGENT_ID", "agent-456");
        Environment.SetEnvironmentVariable("PHANTEX_TRANSPORT", "buffer");
        Environment.SetEnvironmentVariable("PHANTEX_BATCH_SIZE", "100");
        Environment.SetEnvironmentVariable("PHANTEX_DEBUG", "1");

        try
        {
            var cfg = PhantexConfig.FromEnv();
            Assert.Equal("test-token", cfg.AuthToken);
            Assert.Equal("tenant-123", cfg.TenantId);
            Assert.Equal("agent-456", cfg.AgentId);
            Assert.Equal("buffer", cfg.Transport);
            Assert.Equal(100, cfg.BatchSize);
            Assert.True(cfg.Debug);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PHANTEX_TOKEN", null);
            Environment.SetEnvironmentVariable("PHANTEX_TENANT_ID", null);
            Environment.SetEnvironmentVariable("PHANTEX_AGENT_ID", null);
            Environment.SetEnvironmentVariable("PHANTEX_TRANSPORT", null);
            Environment.SetEnvironmentVariable("PHANTEX_BATCH_SIZE", null);
            Environment.SetEnvironmentVariable("PHANTEX_DEBUG", null);
        }
    }
}

public class BufferTransportTests
{
    [Fact]
    public async Task Send_StoresEvents()
    {
        var bt = new BufferTransport(10);
        var evt = new ToolCallEvent { ToolName = "test-tool", Framework = "test" };
        await bt.SendAsync(evt);

        Assert.Equal(1, bt.Count);
        var events = bt.Drain();
        Assert.Single(events);
        Assert.Equal(0, bt.Count);
    }

    [Fact]
    public async Task Send_DropsOldest_WhenFull()
    {
        var bt = new BufferTransport(3);
        for (var i = 0; i < 5; i++)
            await bt.SendAsync(new ToolCallEvent { ToolName = $"tool-{i}" });

        Assert.Equal(3, bt.Count);
    }
}

public class ContextTests
{
    [Fact]
    public void TraceId_GeneratesWhenEmpty()
    {
        PhantexContext.TraceId = "";
        var tid = PhantexContext.TraceId;
        Assert.False(string.IsNullOrEmpty(tid));
        Assert.Equal(32, tid.Length);
    }

    [Fact]
    public void SpanContext_CapturesCurrentValues()
    {
        PhantexContext.TraceId = "trace-abc";
        PhantexContext.SpanId = "span-def";
        PhantexContext.AgentPaid = "agent-ghi";
        PhantexContext.Framework = "test-fw";

        var sc = PhantexContext.Current;
        Assert.Equal("trace-abc", sc.TraceId);
        Assert.Equal("span-def", sc.SpanId);
        Assert.Equal("agent-ghi", sc.AgentPaid);
        Assert.Equal("test-fw", sc.Framework);
    }
}

public class EventTests
{
    [Fact]
    public void ToolCallEvent_HasDefaults()
    {
        var evt = new ToolCallEvent();
        Assert.Equal((int)EventType.ToolCall, evt.EventTypeCode);
        Assert.False(string.IsNullOrEmpty(evt.EventId));
        Assert.True(evt.TimestampNs > 0);
    }

    [Fact]
    public void ToolResponseEvent_HasDefaults()
    {
        var evt = new ToolResponseEvent();
        Assert.Equal((int)EventType.ToolResponse, evt.EventTypeCode);
        Assert.True(evt.Success);
    }

    [Fact]
    public void HashPrompt_IsDeterministic()
    {
        var h1 = EventHelpers.HashPrompt("hello world");
        var h2 = EventHelpers.HashPrompt("hello world");
        Assert.Equal(h1, h2);
        Assert.Equal(64, h1.Length);
    }

    [Fact]
    public void ToJson_SerializesCorrectly()
    {
        var evt = new ToolCallEvent { ToolName = "my-tool", Framework = "test" };
        var json = Encoding.UTF8.GetString(evt.ToJson());
        Assert.Contains("my-tool", json);
        Assert.Contains("test", json);
    }
}

public class ClientTests
{
    [Fact]
    public async Task StartStop_Works()
    {
        var cfg = new PhantexConfig { Transport = "buffer", Hooks = "none" };
        await using var client = new PhantexClient(cfg);

        Assert.False(client.Started);
        await client.StartAsync();
        Assert.True(client.Started);
        await client.StopAsync();
        Assert.False(client.Started);
    }

    [Fact]
    public async Task Disabled_DoesNotStart()
    {
        var cfg = new PhantexConfig { Enabled = false };
        await using var client = new PhantexClient(cfg);
        await client.StartAsync();
        Assert.False(client.Started);
    }
}
