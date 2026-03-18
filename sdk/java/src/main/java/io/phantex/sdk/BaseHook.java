package io.phantex.sdk;

import java.util.logging.Logger;

/**
 * Base class for framework hooks.
 * Provides event emission helpers — hook failure never breaks user code.
 */
public abstract class BaseHook implements PhantexHook {

    protected static final Logger LOG = Logger.getLogger("io.phantex.sdk.hooks");

    protected final PhantexTransport.Transport transport;
    protected final PhantexConfig config;
    protected boolean installed = false;

    protected BaseHook(PhantexTransport.Transport transport, PhantexConfig config) {
        this.transport = transport;
        this.config = config;
    }

    @Override
    public boolean isInstalled() { return installed; }

    @Override
    public void uninstall() { installed = false; }

    /**
     * Emit a tool call event. Returns [spanId, startNs].
     */
    protected String[] emitToolCall(String toolName, String protocol, Object toolInput) {
        String spanId = PhantexContext.newSpanId();
        long startNs = System.nanoTime();
        try {
            var event = new PhantexEvents.ToolCallEvent(toolName, protocol, toolInput);
            event.tenantId      = config.tenantId();
            event.agentId       = PhantexContext.agentPaid();
            event.traceId       = PhantexContext.traceId();
            event.spanId        = spanId;
            event.parentSpanId  = PhantexContext.parentSpanId();
            event.framework     = framework();
            transport.send(event);
        } catch (Exception e) {
            // Never break user code
        }
        return new String[]{ spanId, String.valueOf(startNs) };
    }

    /**
     * Emit a tool response event.
     */
    protected void emitToolResponse(String toolName, String protocol, String spanId,
                                     long startNs, boolean success, String error) {
        try {
            long durationNs = System.nanoTime() - startNs;
            var event = new PhantexEvents.ToolResponseEvent(
                    toolName, protocol, success, durationNs, error);
            event.tenantId      = config.tenantId();
            event.agentId       = PhantexContext.agentPaid();
            event.traceId       = PhantexContext.traceId();
            event.spanId        = spanId;
            event.parentSpanId  = PhantexContext.parentSpanId();
            event.framework     = framework();
            transport.send(event);
        } catch (Exception e) {
            // Never break user code
        }
    }
}
