package io.phantex.sdk;

import java.util.UUID;

/**
 * Thread-local trace context for correlating events.
 *
 * <p>Uses ThreadLocal — each thread gets its own trace/span context.
 */
public final class PhantexContext {

    private static final ThreadLocal<String> TRACE_ID       = new ThreadLocal<>();
    private static final ThreadLocal<String> SPAN_ID        = new ThreadLocal<>();
    private static final ThreadLocal<String> PARENT_SPAN_ID = new ThreadLocal<>();
    private static final ThreadLocal<String> AGENT_PAID     = new ThreadLocal<>();
    private static final ThreadLocal<String> FRAMEWORK      = new ThreadLocal<>();

    private PhantexContext() {}

    public static String newTraceId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    public static String newSpanId() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    public static String traceId() {
        String tid = TRACE_ID.get();
        if (tid == null || tid.isEmpty()) {
            tid = newTraceId();
            TRACE_ID.set(tid);
        }
        return tid;
    }

    public static void setTraceId(String traceId) { TRACE_ID.set(traceId); }

    public static String spanId()           { String v = SPAN_ID.get(); return v != null ? v : ""; }
    public static void   setSpanId(String v){ SPAN_ID.set(v); }

    public static String parentSpanId()            { String v = PARENT_SPAN_ID.get(); return v != null ? v : ""; }
    public static void   setParentSpanId(String v) { PARENT_SPAN_ID.set(v); }

    public static String agentPaid() {
        String v = AGENT_PAID.get();
        if (v == null || v.isEmpty()) {
            v = System.getenv("PHANTEX_AGENT_ID");
            if (v != null && !v.isEmpty()) {
                AGENT_PAID.set(v);
            } else {
                v = "";
            }
        }
        return v;
    }

    public static void setAgentPaid(String v) { AGENT_PAID.set(v); }

    public static String framework()            { String v = FRAMEWORK.get(); return v != null ? v : ""; }
    public static void   setFramework(String v) { FRAMEWORK.set(v); }

    /** Execute a runnable within a child span, restoring context afterwards. */
    public static String withSpan(String frameworkName, Runnable runnable) {
        String oldSpan   = spanId();
        String oldParent = parentSpanId();
        String oldFw     = framework();

        String childSpan = newSpanId();
        setParentSpanId(oldSpan);
        setSpanId(childSpan);
        if (frameworkName != null) setFramework(frameworkName);

        try {
            runnable.run();
        } finally {
            setSpanId(oldSpan);
            setParentSpanId(oldParent);
            setFramework(oldFw);
        }
        return childSpan;
    }
}
