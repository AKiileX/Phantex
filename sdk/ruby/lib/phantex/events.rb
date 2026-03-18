# frozen_string_literal: true

require "digest"
require "json"
require "securerandom"

module Phantex
  # Event type codes — matches proto/phantex/v1/events.proto.
  module EventType
    UNSPECIFIED        = 0
    PROCESS_EXEC       = 1
    PROCESS_EXIT       = 2
    FILE_OPEN          = 10
    FILE_WRITE         = 11
    FILE_READ          = 12
    NETWORK_CONNECT    = 20
    NETWORK_ACCEPT     = 21
    NETWORK_DNS        = 22
    MEMORY_MMAP        = 30
    AGENT_DISCOVERED   = 40
    AGENT_TERMINATED   = 41
    TOOL_CALL          = 50
    TOOL_RESPONSE      = 51
    ALERT_FIRED        = 60
  end

  # Severity levels — matches proto/phantex/v1/events.proto.
  module Severity
    UNSPECIFIED = 0
    INFO        = 1
    LOW         = 2
    MEDIUM      = 3
    HIGH        = 4
    CRITICAL    = 5
  end

  # Base event with common envelope fields.
  class Event
    attr_accessor :event_id, :tenant_id, :agent_id, :sensor_id,
                  :event_type, :severity, :timestamp_ns,
                  :trace_id, :span_id, :parent_span_id,
                  :framework, :extra

    def initialize(event_type:, **kwargs)
      @event_id       = kwargs[:event_id]       || SecureRandom.hex(16)
      @tenant_id      = kwargs[:tenant_id]      || ""
      @agent_id       = kwargs[:agent_id]       || ""
      @sensor_id      = kwargs[:sensor_id]      || ""
      @event_type     = event_type
      @severity       = kwargs[:severity]        || Severity::INFO
      @timestamp_ns   = kwargs[:timestamp_ns]    || (Time.now.to_f * 1_000_000_000).to_i
      @trace_id       = kwargs[:trace_id]        || ""
      @span_id        = kwargs[:span_id]         || ""
      @parent_span_id = kwargs[:parent_span_id]  || ""
      @framework      = kwargs[:framework]       || ""
      @extra          = kwargs[:extra]           || {}
    end

    def to_h
      {
        event_id:       @event_id,
        tenant_id:      @tenant_id,
        agent_id:       @agent_id,
        sensor_id:      @sensor_id,
        event_type:     @event_type,
        severity:       @severity,
        timestamp_ns:   @timestamp_ns,
        trace_id:       @trace_id,
        span_id:        @span_id,
        parent_span_id: @parent_span_id,
        framework:      @framework,
      }.merge(@extra)
    end

    def to_json(*_args)
      JSON.generate(to_h)
    end
  end

  # Tool call event — emitted when an AI framework invokes a tool.
  class ToolCallEvent < Event
    attr_accessor :tool_name, :tool_input, :protocol

    def initialize(tool_name:, protocol: "unknown", tool_input: nil, **kwargs)
      super(event_type: EventType::TOOL_CALL, **kwargs)
      @tool_name  = tool_name
      @protocol   = protocol
      @tool_input = tool_input
    end

    def to_h
      super.merge(
        tool_name:  @tool_name,
        protocol:   @protocol,
        tool_input: safe_serialize(@tool_input),
      )
    end

    private

    def safe_serialize(obj, max_bytes: 4096)
      return "" if obj.nil?

      raw = JSON.generate(obj)
      return raw if raw.bytesize <= max_bytes

      # Truncate by bytes, then ensure we don't split a multi-byte character
      truncated = raw.byteslice(0, max_bytes - 3)&.scrub("") || ""
      "#{truncated}..."
    rescue StandardError
      "<unserializable>"
    end
  end

  # Tool response event — emitted after a tool call completes.
  class ToolResponseEvent < Event
    attr_accessor :tool_name, :protocol, :success, :duration_ns, :error_message

    def initialize(tool_name:, protocol: "unknown", success: true, duration_ns: 0, error_message: nil, **kwargs)
      super(event_type: EventType::TOOL_RESPONSE, **kwargs)
      @tool_name     = tool_name
      @protocol      = protocol
      @success       = success
      @duration_ns   = duration_ns
      @error_message = error_message
    end

    def to_h
      h = super.merge(
        tool_name:   @tool_name,
        protocol:    @protocol,
        success:     @success,
        duration_ns: @duration_ns,
      )
      h[:error_message] = @error_message if @error_message
      h
    end
  end

  # Hash prompt content — never store plaintext.
  def self.hash_prompt(prompt)
    Digest::SHA256.hexdigest(prompt.to_s)
  end
end
