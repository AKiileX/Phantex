using System.Diagnostics;

namespace Phantex.SDK;

/// <summary>
/// Main Phantex SDK client for .NET. Manages hooks, transport and configuration.
/// </summary>
public sealed class PhantexClient : IAsyncDisposable
{
    private readonly PhantexConfig _config;
    private ITransport? _transport;
    private readonly List<IPhantexHook> _hooks = [];
    private bool _started;

    public PhantexClient(PhantexConfig? config = null)
    {
        _config = config ?? PhantexConfig.FromEnv();
    }

    public PhantexConfig Config => _config;
    public ITransport? Transport => _transport;
    public IReadOnlyList<IPhantexHook> Hooks => _hooks.AsReadOnly();
    public bool Started => _started;

    /// <summary>
    /// Start the SDK — initialise transport and install hooks.
    /// </summary>
    public async Task StartAsync(CancellationToken ct = default)
    {
        if (_started) return;
        if (!_config.Enabled)
        {
            if (_config.Debug) Console.Error.WriteLine("phantex: SDK disabled (PHANTEX_ENABLED=0)");
            return;
        }

        _transport = TransportFactory.Create(_config);

        // Install hooks
        foreach (var hook in HookRegistry.CreateAll(_transport, _config))
        {
            try
            {
                if (hook.Install())
                {
                    _hooks.Add(hook);
                    if (_config.Debug) Console.Error.WriteLine($"phantex: hook '{hook.Name}' installed");
                }
            }
            catch (Exception ex)
            {
                if (_config.Debug) Console.Error.WriteLine($"phantex: hook '{hook.Name}' failed: {ex.Message}");
            }
        }

        _started = true;
        if (_config.Debug)
            Console.Error.WriteLine($"phantex: started — hooks: {string.Join(", ", _hooks.Select(h => h.Name))}");
    }

    /// <summary>
    /// Stop the SDK — uninstall hooks and flush transport.
    /// </summary>
    public async Task StopAsync(CancellationToken ct = default)
    {
        if (!_started) return;

        foreach (var hook in _hooks)
            hook.Uninstall();
        _hooks.Clear();

        if (_transport is not null)
        {
            await _transport.FlushAsync(ct);
            await _transport.DisposeAsync();
        }

        _started = false;
        if (_config.Debug) Console.Error.WriteLine("phantex: stopped");
    }

    public async ValueTask DisposeAsync() => await StopAsync();
}
