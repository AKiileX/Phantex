# frozen_string_literal: true

require "securerandom"

module Phantex
  # Thread-local trace context for correlating events.
  #
  # Uses Thread.current store — safe for threaded Ruby servers.
  # Each thread gets its own trace/span IDs.
  module Context
    module_function

    def new_trace_id
      SecureRandom.hex(16) # 32-char hex string
    end

    def new_span_id
      SecureRandom.hex(8) # 16-char hex string
    end

    def trace_id
      Thread.current[:phantex_trace_id] ||= new_trace_id
    end

    def trace_id=(val)
      Thread.current[:phantex_trace_id] = val
    end

    def span_id
      Thread.current[:phantex_span_id] || ""
    end

    def span_id=(val)
      Thread.current[:phantex_span_id] = val
    end

    def parent_span_id
      Thread.current[:phantex_parent_span_id] || ""
    end

    def parent_span_id=(val)
      Thread.current[:phantex_parent_span_id] = val
    end

    def agent_paid
      Thread.current[:phantex_agent_paid] || ENV.fetch("PHANTEX_AGENT_ID", "")
    end

    def agent_paid=(val)
      Thread.current[:phantex_agent_paid] = val
    end

    def framework
      Thread.current[:phantex_framework] || ""
    end

    def framework=(val)
      Thread.current[:phantex_framework] = val
    end

    # Execute a block within a child span context.
    def with_span(framework_name: nil)
      old_span    = span_id
      old_parent  = parent_span_id
      old_fw      = self.framework

      self.parent_span_id = old_span
      self.span_id        = new_span_id
      self.framework      = framework_name if framework_name

      yield span_id
    ensure
      self.span_id        = old_span
      self.parent_span_id = old_parent
      self.framework      = old_fw
    end
  end
end
