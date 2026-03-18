# frozen_string_literal: true

module Phantex
  # SDK configuration — read from environment variables.
  #
  # All env vars are prefixed PHANTEX_:
  #   PHANTEX_TOKEN          Auth token for sensor/gateway
  #   PHANTEX_TENANT_ID      Tenant UUID
  #   PHANTEX_AGENT_ID       Agent PAID
  #   PHANTEX_TRANSPORT      auto|http|buffer (default: auto)
  #   PHANTEX_GATEWAY_ADDR   Gateway address (default: localhost:50051)
  #   PHANTEX_BATCH_SIZE     Max events per batch (default: 50)
  #   PHANTEX_BATCH_TIMEOUT  Seconds before flushing partial batch (default: 1.0)
  #   PHANTEX_BUFFER_SIZE    Max buffered events (default: 5000)
  #   PHANTEX_HOOKS          auto|ruby_openai,langchainrb|none (default: auto)
  #   PHANTEX_RECORD_PROMPTS 0|1 (default: 0)
  #   PHANTEX_DEBUG          0|1 (default: 0)
  #   PHANTEX_ENABLED        0|1 (default: 1)
  class Config
    attr_reader :auth_token, :tenant_id, :agent_id, :transport, :gateway_addr,
                :batch_size, :batch_timeout, :buffer_size, :hooks,
                :record_prompts, :debug, :enabled

    def initialize( # rubocop:disable Metrics/ParameterLists
      auth_token: "",
      tenant_id: "",
      agent_id: "",
      transport: "auto",
      gateway_addr: "localhost:50051",
      batch_size: 50,
      batch_timeout: 1.0,
      buffer_size: 5000,
      hooks: "auto",
      record_prompts: false,
      debug: false,
      enabled: true
    )
      @auth_token     = auth_token
      @tenant_id      = tenant_id
      @agent_id       = agent_id
      @transport      = transport
      @gateway_addr   = gateway_addr
      @batch_size     = batch_size
      @batch_timeout  = batch_timeout
      @buffer_size    = buffer_size
      @hooks          = hooks
      @record_prompts = record_prompts
      @debug          = debug
      @enabled        = enabled
    end

    def self.from_env
      new(
        auth_token:     ENV.fetch("PHANTEX_TOKEN", ""),
        tenant_id:      ENV.fetch("PHANTEX_TENANT_ID", ""),
        agent_id:       ENV.fetch("PHANTEX_AGENT_ID", ""),
        transport:      ENV.fetch("PHANTEX_TRANSPORT", "auto"),
        gateway_addr:   ENV.fetch("PHANTEX_GATEWAY_ADDR", "localhost:50051"),
        batch_size:     ENV.fetch("PHANTEX_BATCH_SIZE", "50").to_i,
        batch_timeout:  ENV.fetch("PHANTEX_BATCH_TIMEOUT", "1.0").to_f,
        buffer_size:    ENV.fetch("PHANTEX_BUFFER_SIZE", "5000").to_i,
        hooks:          ENV.fetch("PHANTEX_HOOKS", "auto"),
        record_prompts: ENV.fetch("PHANTEX_RECORD_PROMPTS", "0") == "1",
        debug:          ENV.fetch("PHANTEX_DEBUG", "0") == "1",
        enabled:        ENV.fetch("PHANTEX_ENABLED", "1") == "1",
      )
    end
  end
end
