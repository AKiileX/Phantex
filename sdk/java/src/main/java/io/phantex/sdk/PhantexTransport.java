package io.phantex.sdk;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * Event transport — ships events to the Phantex gateway.
 *
 * <p>Supported backends:
 * <ul>
 *   <li>BufferTransport — in-memory (testing / fallback)</li>
 *   <li>GrpcTransport — gRPC to gateway (requires grpc-netty on classpath)</li>
 *   <li>HttpTransport — HTTPS POST JSON-L batches to gateway</li>
 * </ul>
 */
public final class PhantexTransport {

    private static final Logger LOG = Logger.getLogger("io.phantex.sdk.transport");
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private PhantexTransport() {}

    /** Transport interface. */
    public interface Transport {
        void send(PhantexEvents.Event event);
        void flush();
        void close();
    }

    // ── Buffer Transport ─────────────────────────────────────────────────

    public static class BufferTransport implements Transport {
        private final List<Map<String, Object>> buffer = new ArrayList<>();
        private final ReentrantLock lock = new ReentrantLock();
        private final int maxSize;

        public BufferTransport(int maxSize) {
            this.maxSize = maxSize;
        }

        public BufferTransport() {
            this(5000);
        }

        @Override
        public void send(PhantexEvents.Event event) {
            lock.lock();
            try {
                if (buffer.size() >= maxSize) {
                    buffer.remove(0);
                }
                buffer.add(event.toMap());
            } finally {
                lock.unlock();
            }
        }

        @Override public void flush() { /* no-op */ }
        @Override public void close() { /* no-op */ }

        public List<Map<String, Object>> drain() {
            lock.lock();
            try {
                List<Map<String, Object>> copy = new ArrayList<>(buffer);
                buffer.clear();
                return copy;
            } finally {
                lock.unlock();
            }
        }

        public int size() {
            lock.lock();
            try { return buffer.size(); }
            finally { lock.unlock(); }
        }
    }

    // ── HTTP Transport ───────────────────────────────────────────────────

    public static class HttpTransport implements Transport {
        private final PhantexConfig config;
        private final HttpClient httpClient;
        private final URI endpoint;
        private final List<Map<String, Object>> batch = new ArrayList<>();
        private final ReentrantLock lock = new ReentrantLock();
        private final ScheduledExecutorService scheduler;
        private volatile boolean closed = false;

        public HttpTransport(PhantexConfig config) {
            this.config = config;
            this.httpClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            this.endpoint = URI.create("https://" + config.gatewayAddr() + "/v1/events");
            this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "phantex-flush");
                t.setDaemon(true);
                return t;
            });
            long intervalMs = (long) (config.batchTimeout() * 1000);
            scheduler.scheduleAtFixedRate(this::flush, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
        }

        @Override
        public void send(PhantexEvents.Event event) {
            if (closed) return;
            lock.lock();
            try {
                batch.add(event.toMap());
                if (batch.size() >= config.batchSize()) {
                    flushBatch();
                }
            } finally {
                lock.unlock();
            }
        }

        @Override
        public void flush() {
            lock.lock();
            try { flushBatch(); }
            finally { lock.unlock(); }
        }

        @Override
        public void close() {
            closed = true;
            flush();
            scheduler.shutdown();
        }

        private void flushBatch() {
            if (batch.isEmpty()) return;
            List<Map<String, Object>> payload = new ArrayList<>(batch);
            batch.clear();

            CompletableFuture.runAsync(() -> postEvents(payload));
        }

        private void postEvents(List<Map<String, Object>> payload) {
            try {
                StringBuilder sb = new StringBuilder();
                for (Map<String, Object> event : payload) {
                    sb.append(GSON.toJson(event)).append('\n');
                }

                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                        .uri(endpoint)
                        .timeout(Duration.ofSeconds(10))
                        .header("Content-Type", "application/x-ndjson")
                        .header("User-Agent", "phantex-java-sdk/0.1.0")
                        .POST(HttpRequest.BodyPublishers.ofString(sb.toString()));

                if (!config.authToken().isEmpty()) {
                    reqBuilder.header("Authorization", "Bearer " + config.authToken());
                }

                HttpResponse<String> resp = httpClient.send(reqBuilder.build(),
                        HttpResponse.BodyHandlers.ofString());

                if (config.debug() && resp.statusCode() >= 400) {
                    LOG.warning("[phantex] HTTP " + resp.statusCode());
                }
            } catch (Exception e) {
                if (config.debug()) {
                    LOG.warning("[phantex] transport error: " + e.getMessage());
                }
            }
        }
    }

    // ── Factory ──────────────────────────────────────────────────────────

    public static Transport create(PhantexConfig config) {
        switch (config.transport()) {
            case "buffer":
                return new BufferTransport(config.bufferSize());
            case "http":
                return new HttpTransport(config);
            case "grpc":
                return createGrpcOrFallback(config);
            case "auto":
                if (!config.gatewayAddr().isEmpty() && !config.authToken().isEmpty()) {
                    return createGrpcOrFallback(config);
                }
                return new BufferTransport(config.bufferSize());
            default:
                return new BufferTransport(config.bufferSize());
        }
    }

    private static Transport createGrpcOrFallback(PhantexConfig config) {
        // Try gRPC if classes are on the classpath, else fall back to HTTP
        try {
            Class.forName("io.grpc.ManagedChannelBuilder");
            return new GrpcTransport(config);
        } catch (ClassNotFoundException e) {
            if (config.debug()) {
                LOG.info("[phantex] gRPC not on classpath, falling back to HTTP");
            }
            return new HttpTransport(config);
        }
    }

    // ── gRPC Transport ───────────────────────────────────────────────────

    /**
     * gRPC transport — uses reflection to avoid hard compile-time dependency.
     * Falls back to HTTP POST (NDJSON) for event delivery until Java proto
     * stubs are generated via buf. The gRPC channel is established for future
     * use once stubs are available.
     */
    public static class GrpcTransport implements Transport {
        private final PhantexConfig config;
        private final HttpClient httpClient;
        private final URI httpEndpoint;
        private final List<Map<String, Object>> batch = new ArrayList<>();
        private final ReentrantLock lock = new ReentrantLock();
        private final ScheduledExecutorService scheduler;
        private volatile boolean closed = false;
        private Object channel; // ManagedChannel

        public GrpcTransport(PhantexConfig config) {
            this.config = config;

            // HTTP client for actual event delivery
            this.httpClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();

            // Build endpoint URL, use https for non-localhost
            String host = config.gatewayAddr().split(":")[0];
            String scheme = ("localhost".equals(host) || "127.0.0.1".equals(host) || "::1".equals(host))
                    ? "http" : "https";
            this.httpEndpoint = URI.create(scheme + "://" + config.gatewayAddr() + "/v1/events");

            this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "phantex-grpc-flush");
                t.setDaemon(true);
                return t;
            });

            try {
                initChannel(config);
            } catch (Exception e) {
                if (config.debug()) {
                    LOG.warning("[phantex] gRPC channel init failed: " + e.getMessage());
                }
            }

            long intervalMs = (long) (config.batchTimeout() * 1000);
            scheduler.scheduleAtFixedRate(this::flush, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
        }

        private void initChannel(PhantexConfig config) throws Exception {
            // Reflective channel construction to avoid compile-time gRPC dependency
            Class<?> mcbClass = Class.forName("io.grpc.ManagedChannelBuilder");
            var builder = mcbClass.getMethod("forTarget", String.class)
                    .invoke(null, config.gatewayAddr());
            // Use plaintext only for exact localhost addresses
            String host = config.gatewayAddr().split(":")[0];
            if ("localhost".equals(host) || "127.0.0.1".equals(host) || "::1".equals(host)) {
                builder = mcbClass.getMethod("usePlaintext").invoke(builder);
            }
            this.channel = mcbClass.getMethod("build").invoke(builder);
        }

        @Override
        public void send(PhantexEvents.Event event) {
            if (closed) return;
            lock.lock();
            try {
                batch.add(event.toMap());
                if (batch.size() >= config.batchSize()) {
                    flushBatch();
                }
            } finally {
                lock.unlock();
            }
        }

        @Override
        public void flush() {
            lock.lock();
            try { flushBatch(); }
            finally { lock.unlock(); }
        }

        @Override
        public void close() {
            closed = true;
            flush();
            scheduler.shutdown();
            try {
                if (channel != null) {
                    channel.getClass().getMethod("shutdown").invoke(channel);
                }
            } catch (Exception e) {
                // best effort
            }
        }

        private void flushBatch() {
            if (batch.isEmpty()) return;
            List<Map<String, Object>> payload = new ArrayList<>(batch);
            batch.clear();

            // Deliver events via HTTP POST (NDJSON) — same gateway endpoint
            CompletableFuture.runAsync(() -> postEvents(payload));
        }

        private void postEvents(List<Map<String, Object>> payload) {
            try {
                StringBuilder sb = new StringBuilder();
                for (Map<String, Object> event : payload) {
                    sb.append(GSON.toJson(event)).append('\n');
                }

                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                        .uri(httpEndpoint)
                        .timeout(Duration.ofSeconds(10))
                        .header("Content-Type", "application/x-ndjson")
                        .header("User-Agent", "phantex-java-sdk/0.1.0")
                        .POST(HttpRequest.BodyPublishers.ofString(sb.toString()));

                if (!config.authToken().isEmpty()) {
                    reqBuilder.header("Authorization", "Bearer " + config.authToken());
                }

                HttpResponse<String> resp = httpClient.send(reqBuilder.build(),
                        HttpResponse.BodyHandlers.ofString());

                if (config.debug() && resp.statusCode() >= 400) {
                    LOG.warning("[phantex] gRPC/HTTP fallback " + resp.statusCode());
                }
            } catch (Exception e) {
                if (config.debug()) {
                    LOG.warning("[phantex] gRPC transport error: " + e.getMessage());
                }
            }
        }
    }
}
