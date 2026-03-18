# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "uri"

module Phantex
  # Transport interface — all transports implement #send, #flush, #close.
  #
  # Supported backends:
  #   BufferTransport — in-memory (testing / fallback)
  #   HTTPTransport   — HTTPS POST JSON-L batches to gateway

  # ---------- Buffer Transport ----------

  class BufferTransport
    attr_reader :events

    def initialize(max_size: 5000)
      @max_size = max_size
      @events   = []
      @mutex    = Mutex.new
    end

    def send(event)
      @mutex.synchronize do
        @events.shift if @events.length >= @max_size
        @events << event.to_h
      end
    end

    def flush; end
    def close; end

    def drain
      @mutex.synchronize do
        drained = @events.dup
        @events.clear
        drained
      end
    end

    def length
      @mutex.synchronize { @events.length }
    end
  end

  # ---------- HTTP Transport ----------

  class HTTPTransport
    def initialize(config)
      @config     = config
      @batch      = []
      @mutex      = Mutex.new
      @uri        = URI.parse("https://#{config.gateway_addr}/v1/events")
      @batch_size = config.batch_size
      @token      = config.auth_token.to_s.gsub(/[\r\n]/, "").strip
      @closed     = false

      # Start background flush thread with graceful shutdown support
      @flush_thread = Thread.new { flush_loop(config.batch_timeout) }
    end

    def send(event)
      return if @closed

      @mutex.synchronize do
        @batch << event.to_h
        flush_batch if @batch.length >= @batch_size
      end
    end

    def flush
      @mutex.synchronize { flush_batch }
    end

    def close
      @closed = true
      flush
      @flush_thread&.join(5) # wait up to 5s for graceful shutdown
    end

    private

    def flush_loop(interval)
      until @closed
        begin
          sleep(interval)
          flush
        rescue StandardError => e
          warn "[phantex] flush error: #{e.message}" if @config.debug
        end
      end
    end

    def flush_batch
      return if @batch.empty?

      payload = @batch.dup
      @batch.clear

      Thread.new do
        post_events(payload)
      end
    end

    def post_events(payload)
      http = Net::HTTP.new(@uri.host, @uri.port)
      http.use_ssl = (@uri.scheme == "https")
      http.min_version = OpenSSL::SSL::TLS1_2_VERSION
      http.open_timeout = 5
      http.read_timeout = 10

      body = payload.map { |e| JSON.generate(e) }.join("\n")
      req = Net::HTTP::Post.new(@uri.path)
      req["Content-Type"]  = "application/x-ndjson"
      req["Authorization"] = "Bearer #{@token}" unless @token.empty?
      req["User-Agent"]    = "phantex-ruby-sdk/#{Phantex::VERSION}"
      req.body = body

      resp = http.request(req)
      warn "[phantex] HTTP #{resp.code}" if @config.debug && resp.code.to_i >= 400
    rescue StandardError => e
      warn "[phantex] transport error: #{e.message}" if @config.debug
    end
  end

  # ---------- Transport Factory ----------

  def self.create_transport(config)
    case config.transport
    when "buffer"
      BufferTransport.new(max_size: config.buffer_size)
    when "http"
      HTTPTransport.new(config)
    when "auto"
      # Try HTTP if gateway is configured and token is present
      if !config.gateway_addr.empty? && !config.auth_token.empty?
        HTTPTransport.new(config)
      else
        BufferTransport.new(max_size: config.buffer_size)
      end
    else
      BufferTransport.new(max_size: config.buffer_size)
    end
  end
end
