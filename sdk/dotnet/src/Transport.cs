using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;

namespace Phantex.SDK;

/// <summary>
/// Transport interface for shipping events to the Phantex gateway.
/// </summary>
public interface ITransport : IAsyncDisposable
{
    Task SendAsync(IPhantexEvent evt, CancellationToken ct = default);
    Task FlushAsync(CancellationToken ct = default);
}

// ---------- Buffer Transport (in-memory, for testing) ----------

public sealed class BufferTransport : ITransport
{
    private readonly ConcurrentQueue<byte[]> _buffer = new();
    private readonly int _maxSize;

    public BufferTransport(int maxSize = 5000) => _maxSize = maxSize;

    public Task SendAsync(IPhantexEvent evt, CancellationToken ct = default)
    {
        while (_buffer.Count >= _maxSize)
            _buffer.TryDequeue(out _);
        _buffer.Enqueue(evt.ToJson());
        return Task.CompletedTask;
    }

    public Task FlushAsync(CancellationToken ct = default) => Task.CompletedTask;
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    public List<byte[]> Drain()
    {
        var items = new List<byte[]>();
        while (_buffer.TryDequeue(out var item))
            items.Add(item);
        return items;
    }

    public List<byte[]> Peek() => _buffer.ToList();
    public int Count => _buffer.Count;
}

// ---------- HTTP Transport ----------

public sealed class HttpTransport : ITransport
{
    private readonly HttpClient _client;
    private readonly PhantexConfig _config;
    private readonly ConcurrentQueue<byte[]> _buffer = new();
    private readonly SemaphoreSlim _flushLock = new(1, 1);
    private readonly Timer _flushTimer;
    private bool _disposed;

    public HttpTransport(PhantexConfig config)
    {
        _config = config;
        _client = new HttpClient(new SocketsHttpHandler
        {
            SslOptions = { EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13 }
        })
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        _flushTimer = new Timer(async _ => { try { await FlushAsync(); } catch { /* timer callback must not throw */ } }, null,
            TimeSpan.FromSeconds(config.BatchTimeout),
            TimeSpan.FromSeconds(config.BatchTimeout));
    }

    public Task SendAsync(IPhantexEvent evt, CancellationToken ct = default)
    {
        if (_disposed) return Task.CompletedTask;
        _buffer.Enqueue(evt.ToJson());
        return _buffer.Count >= _config.BatchSize ? FlushAsync(ct) : Task.CompletedTask;
    }

    public async Task FlushAsync(CancellationToken ct = default)
    {
        if (_buffer.IsEmpty) return;

        await _flushLock.WaitAsync(ct);
        try
        {
            var batch = new List<byte[]>();
            while (batch.Count < _config.BatchSize && _buffer.TryDequeue(out var item))
                batch.Add(item);

            if (batch.Count == 0) return;

            var sb = new StringBuilder();
            foreach (var b in batch)
            {
                sb.Append(Encoding.UTF8.GetString(b));
                sb.Append('\n');
            }

            using var content = new StringContent(sb.ToString(), Encoding.UTF8, "application/x-ndjson");
            using var request = new HttpRequestMessage(HttpMethod.Post, _config.HttpEndpoint) { Content = content };
            if (!string.IsNullOrEmpty(_config.AuthToken))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _config.AuthToken);

            try
            {
                using var resp = await _client.SendAsync(request, ct);
            }
            catch
            {
                // Re-buffer on failure
                foreach (var b in batch)
                    _buffer.Enqueue(b);
            }
        }
        finally
        {
            _flushLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _disposed = true;
        await _flushTimer.DisposeAsync();
        await FlushAsync();
        _client.Dispose();
    }
}

// ---------- gRPC Transport ----------

public sealed class GrpcTransport : ITransport
{
    private readonly PhantexConfig _config;
    private readonly HttpClient _client;
    private readonly ConcurrentQueue<IPhantexEvent> _buffer = new();
    private readonly SemaphoreSlim _flushLock = new(1, 1);
    private readonly Timer _flushTimer;
    private bool _disposed;

    public GrpcTransport(PhantexConfig config)
    {
        _config = config;
        // gRPC transport delegates to HTTP POST (NDJSON) until C# proto stubs
        // are generated via buf. Same gateway /v1/events endpoint.
        _client = new HttpClient(new SocketsHttpHandler
        {
            SslOptions = { EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13 }
        })
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        _flushTimer = new Timer(async _ => { try { await FlushAsync(); } catch { /* timer callback must not throw */ } }, null,
            TimeSpan.FromSeconds(config.BatchTimeout),
            TimeSpan.FromSeconds(config.BatchTimeout));
    }

    public Task SendAsync(IPhantexEvent evt, CancellationToken ct = default)
    {
        if (_disposed) return Task.CompletedTask;
        _buffer.Enqueue(evt);
        return _buffer.Count >= _config.BatchSize ? FlushAsync(ct) : Task.CompletedTask;
    }

    public async Task FlushAsync(CancellationToken ct = default)
    {
        if (_buffer.IsEmpty) return;

        await _flushLock.WaitAsync(ct);
        try
        {
            var batch = new List<IPhantexEvent>();
            while (batch.Count < _config.BatchSize && _buffer.TryDequeue(out var item))
                batch.Add(item);

            if (batch.Count == 0) return;

            var sb = new StringBuilder();
            foreach (var evt in batch)
            {
                sb.Append(Encoding.UTF8.GetString(evt.ToJson()));
                sb.Append('\n');
            }

            using var content = new StringContent(sb.ToString(), Encoding.UTF8, "application/x-ndjson");
            using var request = new HttpRequestMessage(HttpMethod.Post, _config.HttpEndpoint) { Content = content };
            if (!string.IsNullOrEmpty(_config.AuthToken))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _config.AuthToken);

            try
            {
                using var resp = await _client.SendAsync(request, ct);
            }
            catch
            {
                // Re-buffer on failure
                foreach (var evt in batch)
                    _buffer.Enqueue(evt);
            }
        }
        finally
        {
            _flushLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _disposed = true;
        await _flushTimer.DisposeAsync();
        await FlushAsync();
        _client.Dispose();
    }
}

// ---------- Transport Factory ----------

public static class TransportFactory
{
    public static ITransport Create(PhantexConfig config) => config.Transport switch
    {
        "buffer" => new BufferTransport(config.BufferSize),
        "http" => new HttpTransport(config),
        "grpc" => new GrpcTransport(config),
        _ => CreateAuto(config), // "auto"
    };

    private static ITransport CreateAuto(PhantexConfig config)
    {
        try { return new GrpcTransport(config); }
        catch { return new HttpTransport(config); }
    }
}
