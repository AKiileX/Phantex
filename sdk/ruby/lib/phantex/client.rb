# frozen_string_literal: true

module Phantex
  # Main SDK client — manages hooks, transport, and lifecycle.
  #
  # Usage (auto):
  #   require 'phantex'
  #   Phantex.start!
  #
  # Usage (manual):
  #   client = Phantex::Client.new(config: Phantex::Config.from_env)
  #   client.start
  #   # ... run your agent code ...
  #   client.stop
  class Client
    attr_reader :config, :transport, :hooks, :started

    def initialize(config: nil, transport: nil)
      @config    = config || Config.from_env
      @transport = transport || Phantex.create_transport(@config)
      @hooks     = []
      @started   = false

      Context.agent_paid = @config.agent_id unless @config.agent_id.empty?
    end

    def start
      return self if @started
      return self unless @config.enabled

      @hooks = Phantex.install_hooks(@config, @transport)
      @started = true
      warn "[phantex] started (#{@hooks.length} hooks)" if @config.debug
      self
    end

    def stop
      return unless @started

      @hooks.each(&:uninstall)
      @hooks.clear
      @transport.flush
      @transport.close
      @started = false
      warn "[phantex] stopped" if @config.debug
    end

    # Send a custom event.
    def send_event(event)
      @transport.send(event) if @started
    end
  end
end
