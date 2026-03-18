# frozen_string_literal: true

module Phantex
  module Hooks
    # Hook for langchainrb (https://github.com/andreibondarev/langchainrb).
    #
    # Patches:
    #   Langchain::LLM::Base#chat           — capture LLM chat calls
    #   Langchain::Tool::Base#execute       — capture tool executions
    #   Langchain::Chain::Base#call         — capture chain invocations (if available)
    class LangchainRb < Base
      def initialize(**kwargs)
        super
        @name      = "langchainrb"
        @framework = "langchainrb"
      end

      def install
        begin
          require "langchain"
        rescue LoadError
          return false
        end

        patched = false
        patched |= patch_llm_chat
        patched |= patch_tool_execute
        patched |= patch_chain_call
        @installed = patched
        patched
      end

      private

      def patch_llm_chat
        return false unless defined?(::Langchain::LLM::Base) &&
                            ::Langchain::LLM::Base.method_defined?(:chat)

        patch_method(::Langchain::LLM::Base, :chat) do |hook, original, receiver, *args, **kwargs, &blk|
          model_name = receiver.class.name || "unknown_llm"
          span_id, start_ns = hook.emit_tool_call(
            tool_name:  "langchain.llm.#{model_name}",
            protocol:   "langchainrb",
            tool_input: kwargs,
          )
          begin
            result = original.call(*args, **kwargs, &blk)
            hook.emit_tool_response(
              tool_name: "langchain.llm.#{model_name}", span_id: span_id,
              start_ns: start_ns, success: true, protocol: "langchainrb",
            )
            result
          rescue StandardError => e
            hook.emit_tool_response(
              tool_name: "langchain.llm.#{model_name}", span_id: span_id,
              start_ns: start_ns, success: false, protocol: "langchainrb", error: e.message,
            )
            raise
          end
        end
      end

      def patch_tool_execute
        return false unless defined?(::Langchain::Tool::Base) &&
                            ::Langchain::Tool::Base.method_defined?(:execute)

        patch_method(::Langchain::Tool::Base, :execute) do |hook, original, receiver, *args, **kwargs, &blk|
          tool_name = receiver.class.name || "unknown_tool"
          span_id, start_ns = hook.emit_tool_call(
            tool_name:  "langchain.tool.#{tool_name}",
            protocol:   "langchainrb",
            tool_input: args.first,
          )
          begin
            result = original.call(*args, **kwargs, &blk)
            hook.emit_tool_response(
              tool_name: "langchain.tool.#{tool_name}", span_id: span_id,
              start_ns: start_ns, success: true, protocol: "langchainrb",
            )
            result
          rescue StandardError => e
            hook.emit_tool_response(
              tool_name: "langchain.tool.#{tool_name}", span_id: span_id,
              start_ns: start_ns, success: false, protocol: "langchainrb", error: e.message,
            )
            raise
          end
        end
      end

      def patch_chain_call
        return false unless defined?(::Langchain::Chain) &&
                            defined?(::Langchain::Chain::Base) &&
                            ::Langchain::Chain::Base.method_defined?(:call)

        patch_method(::Langchain::Chain::Base, :call) do |hook, original, receiver, *args, **kwargs, &blk|
          chain_name = receiver.class.name || "unknown_chain"
          span_id, start_ns = hook.emit_tool_call(
            tool_name:  "langchain.chain.#{chain_name}",
            protocol:   "langchainrb",
            tool_input: args.first,
          )
          begin
            result = original.call(*args, **kwargs, &blk)
            hook.emit_tool_response(
              tool_name: "langchain.chain.#{chain_name}", span_id: span_id,
              start_ns: start_ns, success: true, protocol: "langchainrb",
            )
            result
          rescue StandardError => e
            hook.emit_tool_response(
              tool_name: "langchain.chain.#{chain_name}", span_id: span_id,
              start_ns: start_ns, success: false, protocol: "langchainrb", error: e.message,
            )
            raise
          end
        end
      end
    end
  end
end
