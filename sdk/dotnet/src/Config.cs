namespace Phantex.SDK;

/// <summary>
/// SDK configuration — read from PHANTEX_* environment variables.
/// </summary>
public sealed class PhantexConfig
{
    public string AuthToken { get; init; } = "";
    public string TenantId { get; init; } = "";
    public string AgentId { get; init; } = "";
    public string Transport { get; init; } = "auto";
    public string GatewayAddr { get; init; } = "localhost:50051";
    public string HttpEndpoint { get; init; } = "https://localhost:8443/v1/events";
    public int BatchSize { get; init; } = 50;
    public double BatchTimeout { get; init; } = 1.0;
    public int BufferSize { get; init; } = 5000;
    public string Hooks { get; init; } = "auto";
    public bool RecordPrompts { get; init; }
    public bool Debug { get; init; }
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Build configuration from PHANTEX_* environment variables.
    /// </summary>
    public static PhantexConfig FromEnv()
    {
        static string Env(string key, string fallback = "") =>
            Environment.GetEnvironmentVariable(key) ?? fallback;

        static int EnvInt(string key, int fallback) =>
            int.TryParse(Environment.GetEnvironmentVariable(key), out var v) ? v : fallback;

        static double EnvDouble(string key, double fallback) =>
            double.TryParse(Environment.GetEnvironmentVariable(key), out var v) ? v : fallback;

        static bool EnvBool(string key, bool fallback) =>
            Environment.GetEnvironmentVariable(key) switch
            {
                "1" => true,
                "0" => false,
                _ => fallback
            };

        return new PhantexConfig
        {
            AuthToken = SanitizeHeader(Env("PHANTEX_TOKEN")),
            TenantId = Env("PHANTEX_TENANT_ID"),
            AgentId = Env("PHANTEX_AGENT_ID"),
            Transport = Env("PHANTEX_TRANSPORT", "auto"),
            GatewayAddr = Env("PHANTEX_GATEWAY_ADDR", "localhost:50051"),
            HttpEndpoint = Env("PHANTEX_HTTP_ENDPOINT", "https://localhost:8443/v1/events"),
            BatchSize = EnvInt("PHANTEX_BATCH_SIZE", 50),
            BatchTimeout = EnvDouble("PHANTEX_BATCH_TIMEOUT", 1.0),
            BufferSize = EnvInt("PHANTEX_BUFFER_SIZE", 5000),
            Hooks = Env("PHANTEX_HOOKS", "auto"),
            RecordPrompts = EnvBool("PHANTEX_RECORD_PROMPTS", false),
            Debug = EnvBool("PHANTEX_DEBUG", false),
            Enabled = EnvBool("PHANTEX_ENABLED", true),
        };
    }

    /// <summary>Strip characters that could enable HTTP header injection.</summary>
    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Trim();
}
