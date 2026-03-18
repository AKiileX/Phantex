# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/phantex"

class TestPhantexConfig < Minitest::Test
  def test_default_config
    config = Phantex::Config.new
    assert_equal "",            config.auth_token
    assert_equal "",            config.tenant_id
    assert_equal "auto",        config.transport
    assert_equal "localhost:50051", config.gateway_addr
    assert_equal 50,            config.batch_size
    assert_equal true,          config.enabled
    assert_equal false,         config.debug
  end

  def test_config_from_env
    ENV["PHANTEX_TOKEN"]     = "test-token-123"
    ENV["PHANTEX_TENANT_ID"] = "tenant-abc"
    ENV["PHANTEX_AGENT_ID"]  = "agent-ruby-1"
    ENV["PHANTEX_DEBUG"]     = "1"

    config = Phantex::Config.from_env
    assert_equal "test-token-123", config.auth_token
    assert_equal "tenant-abc",     config.tenant_id
    assert_equal "agent-ruby-1",   config.agent_id
    assert_equal true,             config.debug
  ensure
    ENV.delete("PHANTEX_TOKEN")
    ENV.delete("PHANTEX_TENANT_ID")
    ENV.delete("PHANTEX_AGENT_ID")
    ENV.delete("PHANTEX_DEBUG")
  end
end

class TestPhantexContext < Minitest::Test
  def test_trace_id_generation
    tid = Phantex::Context.new_trace_id
    assert_equal 32, tid.length
    assert_match(/\A[0-9a-f]+\z/, tid)
  end

  def test_span_id_generation
    sid = Phantex::Context.new_span_id
    assert_equal 16, sid.length
    assert_match(/\A[0-9a-f]+\z/, sid)
  end

  def test_agent_paid_from_env
    ENV["PHANTEX_AGENT_ID"] = "ruby-agent-99"
    Thread.current[:phantex_agent_paid] = nil
    assert_equal "ruby-agent-99", Phantex::Context.agent_paid
  ensure
    ENV.delete("PHANTEX_AGENT_ID")
  end

  def test_with_span_nesting
    Phantex::Context.span_id = "outer"
    Phantex::Context.with_span(framework_name: "test") do |inner_span|
      assert_equal inner_span, Phantex::Context.span_id
      assert_equal "outer", Phantex::Context.parent_span_id
      assert_equal "test", Phantex::Context.framework
    end
    assert_equal "outer", Phantex::Context.span_id
  end
end

class TestPhantexEvents < Minitest::Test
  def test_tool_call_event_serialization
    event = Phantex::ToolCallEvent.new(
      tool_name:  "calculator",
      protocol:   "langchainrb",
      tool_input: { expression: "2+2" },
      tenant_id:  "t-1",
    )
    h = event.to_h
    assert_equal "calculator",  h[:tool_name]
    assert_equal "langchainrb", h[:protocol]
    assert_equal "t-1",         h[:tenant_id]
    assert_equal Phantex::EventType::TOOL_CALL, h[:event_type]
    assert h[:timestamp_ns] > 0
  end

  def test_tool_response_event
    event = Phantex::ToolResponseEvent.new(
      tool_name:   "search",
      protocol:    "openai_api",
      success:     false,
      duration_ns: 42_000_000,
      error_message: "timeout",
    )
    h = event.to_h
    assert_equal false, h[:success]
    assert_equal 42_000_000, h[:duration_ns]
    assert_equal "timeout", h[:error_message]
  end

  def test_hash_prompt
    hash = Phantex.hash_prompt("hello world")
    assert_equal 64, hash.length
    assert_equal hash, Phantex.hash_prompt("hello world") # deterministic
  end
end

class TestBufferTransport < Minitest::Test
  def test_send_and_drain
    transport = Phantex::BufferTransport.new(max_size: 10)
    event = Phantex::ToolCallEvent.new(tool_name: "test", protocol: "test")
    transport.send(event)

    assert_equal 1, transport.length
    drained = transport.drain
    assert_equal 1, drained.length
    assert_equal 0, transport.length
  end

  def test_max_size_eviction
    transport = Phantex::BufferTransport.new(max_size: 2)
    3.times do |i|
      transport.send(Phantex::ToolCallEvent.new(tool_name: "t#{i}", protocol: "test"))
    end
    assert_equal 2, transport.length
  end
end

class TestPhantexClient < Minitest::Test
  def test_client_start_stop
    config = Phantex::Config.new(transport: "buffer", hooks: "none")
    transport = Phantex::BufferTransport.new
    client = Phantex::Client.new(config: config, transport: transport)

    client.start
    assert client.started

    client.stop
    refute client.started
  end

  def test_send_event
    transport = Phantex::BufferTransport.new
    config = Phantex::Config.new(transport: "buffer", hooks: "none")
    client = Phantex::Client.new(config: config, transport: transport)
    client.start

    event = Phantex::ToolCallEvent.new(tool_name: "my_tool", protocol: "custom")
    client.send_event(event)
    assert_equal 1, transport.length
  end

  def test_disabled_client
    config = Phantex::Config.new(enabled: false, hooks: "none")
    client = Phantex::Client.new(config: config)
    client.start
    refute client.started
  end
end
