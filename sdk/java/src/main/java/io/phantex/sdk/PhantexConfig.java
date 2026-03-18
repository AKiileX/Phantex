package io.phantex.sdk;

/**
 * SDK configuration — read from environment variables.
 *
 * <p>All env vars are prefixed PHANTEX_:
 * <ul>
 *   <li>PHANTEX_TOKEN — Auth token</li>
 *   <li>PHANTEX_TENANT_ID — Tenant UUID</li>
 *   <li>PHANTEX_AGENT_ID — Agent PAID</li>
 *   <li>PHANTEX_TRANSPORT — auto|grpc|http|buffer</li>
 *   <li>PHANTEX_GATEWAY_ADDR — Gateway address</li>
 *   <li>PHANTEX_BATCH_SIZE — Max events per batch</li>
 *   <li>PHANTEX_BATCH_TIMEOUT — Seconds before flush</li>
 *   <li>PHANTEX_BUFFER_SIZE — Max buffered events</li>
 *   <li>PHANTEX_HOOKS — auto|langchain4j,spring_ai|none</li>
 *   <li>PHANTEX_RECORD_PROMPTS — 0|1</li>
 *   <li>PHANTEX_DEBUG — 0|1</li>
 *   <li>PHANTEX_ENABLED — 0|1</li>
 * </ul>
 */
public final class PhantexConfig {

    private final String authToken;
    private final String tenantId;
    private final String agentId;
    private final String transport;
    private final String gatewayAddr;
    private final int batchSize;
    private final double batchTimeout;
    private final int bufferSize;
    private final String hooks;
    private final boolean recordPrompts;
    private final boolean debug;
    private final boolean enabled;

    private PhantexConfig(Builder builder) {
        this.authToken     = builder.authToken;
        this.tenantId      = builder.tenantId;
        this.agentId       = builder.agentId;
        this.transport     = builder.transport;
        this.gatewayAddr   = builder.gatewayAddr;
        this.batchSize     = builder.batchSize;
        this.batchTimeout  = builder.batchTimeout;
        this.bufferSize    = builder.bufferSize;
        this.hooks         = builder.hooks;
        this.recordPrompts = builder.recordPrompts;
        this.debug         = builder.debug;
        this.enabled       = builder.enabled;
    }

    /** Build config from environment variables. */
    public static PhantexConfig fromEnv() {
        return new Builder()
            .authToken(sanitizeHeader(env("PHANTEX_TOKEN", "")))
            .tenantId(env("PHANTEX_TENANT_ID", ""))
            .agentId(env("PHANTEX_AGENT_ID", ""))
            .transport(env("PHANTEX_TRANSPORT", "auto"))
            .gatewayAddr(env("PHANTEX_GATEWAY_ADDR", "localhost:50051"))
            .batchSize(envInt("PHANTEX_BATCH_SIZE", 50))
            .batchTimeout(envDouble("PHANTEX_BATCH_TIMEOUT", 1.0))
            .bufferSize(envInt("PHANTEX_BUFFER_SIZE", 5000))
            .hooks(env("PHANTEX_HOOKS", "auto"))
            .recordPrompts("1".equals(env("PHANTEX_RECORD_PROMPTS", "0")))
            .debug("1".equals(env("PHANTEX_DEBUG", "0")))
            .enabled("1".equals(env("PHANTEX_ENABLED", "1")))
            .build();
    }

    public String authToken()     { return authToken; }
    public String tenantId()      { return tenantId; }
    public String agentId()       { return agentId; }
    public String transport()     { return transport; }
    public String gatewayAddr()   { return gatewayAddr; }
    public int    batchSize()     { return batchSize; }
    public double batchTimeout()  { return batchTimeout; }
    public int    bufferSize()    { return bufferSize; }
    public String hooks()         { return hooks; }
    public boolean recordPrompts(){ return recordPrompts; }
    public boolean debug()        { return debug; }
    public boolean enabled()      { return enabled; }

    public static Builder builder() { return new Builder(); }

    private static String env(String key, String defaultVal) {
        String val = System.getenv(key);
        return (val != null && !val.isEmpty()) ? val : defaultVal;
    }

    private static int envInt(String key, int defaultVal) {
        try {
            return Integer.parseInt(env(key, String.valueOf(defaultVal)));
        } catch (NumberFormatException e) {
            return defaultVal;
        }
    }

    private static double envDouble(String key, double defaultVal) {
        try {
            return Double.parseDouble(env(key, String.valueOf(defaultVal)));
        } catch (NumberFormatException e) {
            return defaultVal;
        }
    }

    /** Strip characters that could enable HTTP header injection. */
    private static String sanitizeHeader(String value) {
        return value.replace("\r", "").replace("\n", "").trim();
    }

    public static final class Builder {
        private String authToken    = "";
        private String tenantId     = "";
        private String agentId      = "";
        private String transport    = "auto";
        private String gatewayAddr  = "localhost:50051";
        private int    batchSize    = 50;
        private double batchTimeout = 1.0;
        private int    bufferSize   = 5000;
        private String hooks        = "auto";
        private boolean recordPrompts = false;
        private boolean debug       = false;
        private boolean enabled     = true;

        public Builder authToken(String v)     { this.authToken = v;     return this; }
        public Builder tenantId(String v)      { this.tenantId = v;      return this; }
        public Builder agentId(String v)       { this.agentId = v;       return this; }
        public Builder transport(String v)     { this.transport = v;     return this; }
        public Builder gatewayAddr(String v)   { this.gatewayAddr = v;   return this; }
        public Builder batchSize(int v)        { this.batchSize = v;     return this; }
        public Builder batchTimeout(double v)  { this.batchTimeout = v;  return this; }
        public Builder bufferSize(int v)       { this.bufferSize = v;    return this; }
        public Builder hooks(String v)         { this.hooks = v;         return this; }
        public Builder recordPrompts(boolean v){ this.recordPrompts = v; return this; }
        public Builder debug(boolean v)        { this.debug = v;        return this; }
        public Builder enabled(boolean v)      { this.enabled = v;      return this; }

        public PhantexConfig build() { return new PhantexConfig(this); }
    }
}
