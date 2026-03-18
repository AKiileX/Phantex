# frozen_string_literal: true

module Phantex
  module Hooks
    # Base class for all framework hooks.
    #
    # Provides safe monkey-patching, event emission, and timing.
    # Hook failure never breaks user code.
    class Base
      attr_reader :name, :framework, :installed

      def initialize(transport:, config:)
        @transport = transport
        @config    = config
        @patches   = [] # [[mod, method_name, original_method]]
        @installed = false
        @name      = "base"
        @framework = "unknown"
      end

      def install
        raise NotImplementedError, "#{self.class}#install must be implemented"
      end

      def uninstall
        @patches.reverse_each do |mod, method_name, original|
          mod.define_method(method_name, original)
        rescue StandardError
          # best-effort restore
        end
        @patches.clear
        @installed = false
      end

      protected

      # Safely prepend a wrapper around an instance method.
      def patch_method(mod, method_name, &wrapper_block)
        return false unless mod.method_defined?(method_name) || mod.private_method_defined?(method_name)

        original = mod.instance_method(method_name)
        @patches << [mod, method_name, original]

        hook = self
        mod.define_method(method_name) do |*args, **kwargs, &blk|
          wrapper_block.call(hook, original.bind(self), self, *args, **kwargs, &blk)
        end
        true
      rescue StandardError
        false
      end

      # Emit a tool call event, returns [span_id, start_ns].
      def emit_tool_call(tool_name:, protocol:, tool_input: nil)
        span_id  = Context.new_span_id
        start_ns = (Time.now.to_f * 1_000_000_000).to_i

        event = ToolCallEvent.new(
          tool_name:      tool_name,
          protocol:       protocol,
          tool_input:     tool_input,
          tenant_id:      @config.tenant_id,
          agent_id:       Context.agent_paid,
          trace_id:       Context.trace_id,
          span_id:        span_id,
          parent_span_id: Context.parent_span_id,
          framework:      @framework,
        )
        @transport.send(event)
        [span_id, start_ns]
      rescue StandardError
        [span_id || "", start_ns || 0]
      end

      # Emit a tool response event.
      def emit_tool_response(tool_name:, span_id:, start_ns:, success:, protocol:, error: nil)
        now_ns = (Time.now.to_f * 1_000_000_000).to_i
        event = ToolResponseEvent.new(
          tool_name:      tool_name,
          protocol:       protocol,
          success:        success,
          duration_ns:    now_ns - start_ns,
          error_message:  error,
          tenant_id:      @config.tenant_id,
          agent_id:       Context.agent_paid,
          trace_id:       Context.trace_id,
          span_id:        span_id,
          parent_span_id: Context.parent_span_id,
          framework:      @framework,
        )
        @transport.send(event)
      rescue StandardError
        # Never break user code
      end
    end
  end
end
