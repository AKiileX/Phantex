package io.phantex.sdk;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Event types matching proto/phantex/v1/events.proto.
 */
public final class PhantexEvents {

    private PhantexEvents() {}

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    // Event type codes
    public static final int EVENT_TYPE_UNSPECIFIED        = 0;
    public static final int EVENT_TYPE_PROCESS_EXEC       = 1;
    public static final int EVENT_TYPE_PROCESS_EXIT       = 2;
    public static final int EVENT_TYPE_FILE_OPEN          = 10;
    public static final int EVENT_TYPE_FILE_WRITE         = 11;
    public static final int EVENT_TYPE_FILE_READ          = 12;
    public static final int EVENT_TYPE_NETWORK_CONNECT    = 20;
    public static final int EVENT_TYPE_NETWORK_ACCEPT     = 21;
    public static final int EVENT_TYPE_NETWORK_DNS        = 22;
    public static final int EVENT_TYPE_MEMORY_MMAP        = 30;
    public static final int EVENT_TYPE_AGENT_DISCOVERED   = 40;
    public static final int EVENT_TYPE_AGENT_TERMINATED   = 41;
    public static final int EVENT_TYPE_TOOL_CALL          = 50;
    public static final int EVENT_TYPE_TOOL_RESPONSE      = 51;
    public static final int EVENT_TYPE_ALERT_FIRED        = 60;

    // Severity levels
    public static final int SEVERITY_UNSPECIFIED = 0;
    public static final int SEVERITY_INFO        = 1;
    public static final int SEVERITY_LOW         = 2;
    public static final int SEVERITY_MEDIUM      = 3;
    public static final int SEVERITY_HIGH        = 4;
    public static final int SEVERITY_CRITICAL    = 5;

    /** Base event with common envelope fields. */
    public static class Event {
        public String eventId;
        public String tenantId;
        public String agentId;
        public String sensorId;
        public int    eventType;
        public int    severity;
        public long   timestampNs;
        public String traceId;
        public String spanId;
        public String parentSpanId;
        public String framework;

        public Event(int eventType) {
            this.eventId     = UUID.randomUUID().toString().replace("-", "");
            this.tenantId    = "";
            this.agentId     = "";
            this.sensorId    = "";
            this.eventType   = eventType;
            this.severity    = SEVERITY_INFO;
            this.timestampNs = System.currentTimeMillis() * 1_000_000L;
            this.traceId     = "";
            this.spanId      = "";
            this.parentSpanId = "";
            this.framework    = "";
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("event_id",       eventId);
            m.put("tenant_id",      tenantId);
            m.put("agent_id",       agentId);
            m.put("sensor_id",      sensorId);
            m.put("event_type",     eventType);
            m.put("severity",       severity);
            m.put("timestamp_ns",   timestampNs);
            m.put("trace_id",       traceId);
            m.put("span_id",        spanId);
            m.put("parent_span_id", parentSpanId);
            m.put("framework",      framework);
            return m;
        }

        public String toJson() {
            return GSON.toJson(toMap());
        }
    }

    /** Tool call event. */
    public static class ToolCallEvent extends Event {
        public String toolName;
        public String protocol;
        public Object toolInput;

        public ToolCallEvent(String toolName, String protocol, Object toolInput) {
            super(EVENT_TYPE_TOOL_CALL);
            this.toolName  = toolName;
            this.protocol  = protocol;
            this.toolInput = toolInput;
        }

        @Override
        public Map<String, Object> toMap() {
            Map<String, Object> m = super.toMap();
            m.put("tool_name", toolName);
            m.put("protocol",  protocol);
            m.put("tool_input", safeSerialize(toolInput, 4096));
            return m;
        }
    }

    /** Tool response event. */
    public static class ToolResponseEvent extends Event {
        public String  toolName;
        public String  protocol;
        public boolean success;
        public long    durationNs;
        public String  errorMessage;

        public ToolResponseEvent(String toolName, String protocol, boolean success,
                                  long durationNs, String errorMessage) {
            super(EVENT_TYPE_TOOL_RESPONSE);
            this.toolName     = toolName;
            this.protocol     = protocol;
            this.success      = success;
            this.durationNs   = durationNs;
            this.errorMessage = errorMessage;
        }

        @Override
        public Map<String, Object> toMap() {
            Map<String, Object> m = super.toMap();
            m.put("tool_name",   toolName);
            m.put("protocol",    protocol);
            m.put("success",     success);
            m.put("duration_ns", durationNs);
            if (errorMessage != null) m.put("error_message", errorMessage);
            return m;
        }
    }

    /** SHA-256 hash of prompt content — never store plaintext. */
    public static String hashPrompt(String prompt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(prompt.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    static String safeSerialize(Object obj, int maxChars) {
        if (obj == null) return "";
        try {
            String raw = GSON.toJson(obj);
            if (raw.length() <= maxChars) return raw;
            // Avoid splitting a surrogate pair
            int cut = maxChars - 3;
            if (cut > 0 && Character.isHighSurrogate(raw.charAt(cut - 1))) {
                cut--;
            }
            return raw.substring(0, cut) + "...";
        } catch (Exception e) {
            return "<unserializable>";
        }
    }
}
