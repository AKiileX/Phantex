package io.phantex.sdk;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PhantexSDKTest {

    @Test
    void testDefaultConfig() {
        var config = PhantexConfig.builder().build();
        assertEquals("", config.authToken());
        assertEquals("", config.tenantId());
        assertEquals("auto", config.transport());
        assertEquals("localhost:50051", config.gatewayAddr());
        assertEquals(50, config.batchSize());
        assertTrue(config.enabled());
        assertFalse(config.debug());
    }

    @Test
    void testConfigBuilder() {
        var config = PhantexConfig.builder()
                .authToken("test-token")
                .tenantId("tenant-123")
                .agentId("agent-java-1")
                .transport("buffer")
                .hooks("none")
                .debug(true)
                .build();

        assertEquals("test-token", config.authToken());
        assertEquals("tenant-123", config.tenantId());
        assertEquals("agent-java-1", config.agentId());
        assertEquals("buffer", config.transport());
        assertEquals("none", config.hooks());
        assertTrue(config.debug());
    }

    @Test
    void testContext() {
        String tid = PhantexContext.newTraceId();
        assertEquals(32, tid.length());
        assertTrue(tid.matches("[0-9a-f]+"));

        String sid = PhantexContext.newSpanId();
        assertEquals(16, sid.length());
        assertTrue(sid.matches("[0-9a-f]+"));
    }

    @Test
    void testContextWithSpan() {
        PhantexContext.setSpanId("outer");
        PhantexContext.withSpan("test", () -> {
            assertNotEquals("outer", PhantexContext.spanId());
            assertEquals("outer", PhantexContext.parentSpanId());
            assertEquals("test", PhantexContext.framework());
        });
        assertEquals("outer", PhantexContext.spanId());
    }

    @Test
    void testToolCallEvent() {
        var event = new PhantexEvents.ToolCallEvent("calculator", "langchain4j", Map.of("expr", "2+2"));
        event.tenantId = "t-1";

        Map<String, Object> m = event.toMap();
        assertEquals("calculator", m.get("tool_name"));
        assertEquals("langchain4j", m.get("protocol"));
        assertEquals("t-1", m.get("tenant_id"));
        assertEquals(PhantexEvents.EVENT_TYPE_TOOL_CALL, m.get("event_type"));
    }

    @Test
    void testToolResponseEvent() {
        var event = new PhantexEvents.ToolResponseEvent(
                "search", "spring_ai", false, 42_000_000L, "timeout");

        Map<String, Object> m = event.toMap();
        assertEquals(false, m.get("success"));
        assertEquals(42_000_000L, m.get("duration_ns"));
        assertEquals("timeout", m.get("error_message"));
    }

    @Test
    void testHashPrompt() {
        String hash = PhantexEvents.hashPrompt("hello world");
        assertEquals(64, hash.length());
        assertEquals(hash, PhantexEvents.hashPrompt("hello world")); // deterministic
    }

    @Test
    void testBufferTransport() {
        var transport = new PhantexTransport.BufferTransport(10);
        var event = new PhantexEvents.ToolCallEvent("test", "test", null);
        transport.send(event);

        assertEquals(1, transport.size());
        List<Map<String, Object>> drained = transport.drain();
        assertEquals(1, drained.size());
        assertEquals(0, transport.size());
    }

    @Test
    void testBufferMaxSize() {
        var transport = new PhantexTransport.BufferTransport(2);
        for (int i = 0; i < 3; i++) {
            transport.send(new PhantexEvents.ToolCallEvent("t" + i, "test", null));
        }
        assertEquals(2, transport.size());
    }

    @Test
    void testClientStartStop() {
        var transport = new PhantexTransport.BufferTransport();
        var config = PhantexConfig.builder().transport("buffer").hooks("none").build();
        var client = PhantexClient.builder().config(config).transport(transport).build();

        client.start();
        assertTrue(client.isStarted());

        client.stop();
        assertFalse(client.isStarted());
    }

    @Test
    void testSendEvent() {
        var transport = new PhantexTransport.BufferTransport();
        var config = PhantexConfig.builder().transport("buffer").hooks("none").build();
        var client = PhantexClient.builder().config(config).transport(transport).build();
        client.start();

        var event = new PhantexEvents.ToolCallEvent("my_tool", "custom", null);
        client.sendEvent(event);
        assertEquals(1, transport.size());
    }

    @Test
    void testDisabledClient() {
        var config = PhantexConfig.builder().enabled(false).hooks("none").build();
        var client = PhantexClient.builder().config(config).build();
        client.start();
        assertFalse(client.isStarted());
    }

    @Test
    void testEventJson() {
        var event = new PhantexEvents.ToolCallEvent("calc", "test", Map.of("x", 1));
        event.tenantId = "t-1";
        String json = event.toJson();
        assertTrue(json.contains("\"tool_name\":\"calc\""));
        assertTrue(json.contains("\"tenant_id\":\"t-1\""));
    }
}
