# frozen_string_literal: true

module Phantex
  module Hooks
    # Hook for the ruby-openai gem (https://github.com/alexrudall/ruby-openai).
    #
    # Patches:
    #   OpenAI::Client#chat          — capture chat completions
    #   OpenAI::Client#completions   — capture legacy completions
    #   OpenAI::Client#embeddings    — capture embedding calls
    class RubyOpenAI < Base
      def initialize(**kwargs)
        super
        @name      = "ruby_openai"
        @framework = "openai"
      end

      def install
        begin
          require "openai"
        rescue LoadError
          return false
        end

        return false unless defined?(::OpenAI::Client)

        patched = false
        patched |= patch_chat
        patched |= patch_completions
        patched |= patch_embeddings
        @installed = patched
        patched
      end

      private

      def patch_chat
        return false unless ::OpenAI::Client.method_defined?(:chat)

        patch_method(::OpenAI::Client, :chat) do |hook, original, _receiver, *args, **kwargs, &blk|
          model = kwargs.dig(:parameters, :model) || "unknown"
          span_id, start_ns = hook.emit_tool_call(
            tool_name:  "openai.chat.#{model}",
            protocol:   "openai_api",
            tool_input: kwargs[:parameters],
          )
          begin
            result = original.call(*args, **kwargs, &blk)
            hook.emit_tool_response(
              tool_name: "openai.chat.#{model}", span_id: span_id,
              start_ns: start_ns, success: true, protocol: "openai_api",
            )
            result
          rescue StandardError => e
            hook.emit_tool_response(
              tool_name: "openai.chat.#{model}", span_id: span_id,
              start_ns: start_ns, success: false, protocol: "openai_api", error: e.message,
            )
            raise
          end
        end
      end

      def patch_completions
        return false unless ::OpenAI::Client.method_defined?(:completions)

        patch_method(::OpenAI::Client, :completions) do |hook, original, _receiver, *args, **kwargs, &blk|
          span_id, start_ns = hook.emit_tool_call(
            tool_name: "openai.completions", protocol: "openai_api", tool_input: kwargs[:parameters],
          )
          begin
            result = original.call(*args, **kwargs, &blk)
            hook.emit_tool_response(
              tool_name: "openai.completions", span_id: span_id,
              start_ns: start_ns, success: true, protocol: "openai_api",
            )
            result
          rescue StandardError => e
            hook.emit_tool_response(
              tool_name: "openai.completions", span_id: span_id,
              start_ns: start_ns, success: false, protocol: "openai_api", error: e.message,
            )
            raise
          end
        end
      end

      def patch_embeddings
        return false unless ::OpenAI::Client.method_defined?(:embeddings)

        patch_method(::OpenAI::Client, :embeddings) do |hook, original, _receiver, *args, **kwargs, &blk|
          span_id, start_ns = hook.emit_tool_call(
            tool_name: "openai.embeddings", protocol: "openai_api", tool_input: kwargs[:parameters],
          )
          begin
            result = original.call(*args, **kwargs, &blk)
            hook.emit_tool_response(
              tool_name: "openai.embeddings", span_id: span_id,
              start_ns: start_ns, success: true, protocol: "openai_api",
            )
            result
          rescue StandardError => e
            hook.emit_tool_response(
              tool_name: "openai.embeddings", span_id: span_id,
              start_ns: start_ns, success: false, protocol: "openai_api", error: e.message,
            )
            raise
          end
        end
      end
    end
  end
end
