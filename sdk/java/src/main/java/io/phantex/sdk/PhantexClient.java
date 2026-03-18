package io.phantex.sdk;

import io.phantex.sdk.hooks.LangChain4jHook;
import io.phantex.sdk.hooks.SpringAIHook;

import java.util.*;
import java.util.logging.Logger;

/**
 * Main Phantex SDK client — manages hooks, transport, and lifecycle.
 *
 * <p>Usage:
 * <pre>
 *   var client = PhantexClient.create();   // config from env
 *   client.start();
 *   // ... your AI agent code ...
 *   client.stop();
 * </pre>
 *
 * <p>Or with builder:
 * <pre>
 *   var client = PhantexClient.builder()
 *       .config(PhantexConfig.builder().hooks("langchain4j").build())
 *       .build();
 *   client.start();
 * </pre>
 */
public final class PhantexClient {

    private static final Logger LOG = Logger.getLogger("io.phantex.sdk");

    private final PhantexConfig config;
    private final PhantexTransport.Transport transport;
    private final List<PhantexHook> hooks = new ArrayList<>();
    private boolean started = false;

    // Hook registry
    private static final Map<String, HookFactory> HOOK_REGISTRY = new LinkedHashMap<>();

    @FunctionalInterface
    interface HookFactory {
        PhantexHook create(PhantexTransport.Transport transport, PhantexConfig config);
    }

    static {
        HOOK_REGISTRY.put("langchain4j", LangChain4jHook::new);
        HOOK_REGISTRY.put("spring_ai",   SpringAIHook::new);
    }

    private PhantexClient(PhantexConfig config, PhantexTransport.Transport transport) {
        this.config = config;
        this.transport = transport;

        if (config.agentId() != null && !config.agentId().isEmpty()) {
            PhantexContext.setAgentPaid(config.agentId());
        }
    }

    /** Create client with config from environment variables. */
    public static PhantexClient create() {
        PhantexConfig cfg = PhantexConfig.fromEnv();
        return new PhantexClient(cfg, PhantexTransport.create(cfg));
    }

    public static Builder builder() { return new Builder(); }

    public PhantexConfig config()                  { return config; }
    public PhantexTransport.Transport transport()  { return transport; }
    public List<PhantexHook> hooks()               { return Collections.unmodifiableList(hooks); }
    public boolean isStarted()                     { return started; }

    /** Start the client — install hooks and begin capturing events. */
    public PhantexClient start() {
        if (started) return this;
        if (!config.enabled()) return this;

        String hooksConfig = config.hooks().toLowerCase().trim();
        if (!"none".equals(hooksConfig)) {
            List<String> names = "auto".equals(hooksConfig)
                    ? new ArrayList<>(HOOK_REGISTRY.keySet())
                    : Arrays.asList(hooksConfig.split(","));

            for (String name : names) {
                String trimmed = name.trim();
                HookFactory factory = HOOK_REGISTRY.get(trimmed);
                if (factory == null) continue;

                try {
                    PhantexHook hook = factory.create(transport, config);
                    if (hook.install()) {
                        hooks.add(hook);
                    }
                } catch (Exception e) {
                    if (config.debug()) {
                        LOG.warning("[phantex] failed to install hook " + trimmed + ": " + e.getMessage());
                    }
                }
            }
        }

        started = true;
        if (config.debug()) {
            LOG.info("[phantex] started (" + hooks.size() + " hooks)");
        }
        return this;
    }

    /** Stop the client — uninstall hooks, flush, and close transport. */
    public void stop() {
        if (!started) return;
        for (PhantexHook hook : hooks) {
            hook.uninstall();
        }
        hooks.clear();
        transport.flush();
        transport.close();
        started = false;
        if (config.debug()) {
            LOG.info("[phantex] stopped");
        }
    }

    /** Send a custom event. */
    public void sendEvent(PhantexEvents.Event event) {
        if (started) {
            transport.send(event);
        }
    }

    /**
     * Get a hook by type for wrapping framework objects.
     * <pre>
     *   LangChain4jHook lc = client.hook(LangChain4jHook.class);
     *   ChatLanguageModel wrapped = lc.wrap(model);
     * </pre>
     */
    @SuppressWarnings("unchecked")
    public <T extends PhantexHook> T hook(Class<T> hookClass) {
        for (PhantexHook hook : hooks) {
            if (hookClass.isInstance(hook)) {
                return (T) hook;
            }
        }
        return null;
    }

    public static final class Builder {
        private PhantexConfig config;
        private PhantexTransport.Transport transport;

        public Builder config(PhantexConfig config)                  { this.config = config;       return this; }
        public Builder transport(PhantexTransport.Transport transport){ this.transport = transport; return this; }

        public PhantexClient build() {
            if (config == null) config = PhantexConfig.fromEnv();
            if (transport == null) transport = PhantexTransport.create(config);
            return new PhantexClient(config, transport);
        }
    }
}
