# frozen_string_literal: true

require_relative "hooks/base"
require_relative "hooks/ruby_openai"
require_relative "hooks/langchainrb"

module Phantex
  # Hook registry — maps hook name to class.
  HOOK_REGISTRY = {
    "ruby_openai"  => Hooks::RubyOpenAI,
    "langchainrb"  => Hooks::LangchainRb,
  }.freeze

  def self.install_hooks(config, transport)
    hooks_config = config.hooks.downcase.strip
    return [] if hooks_config == "none"

    names = if hooks_config == "auto"
              HOOK_REGISTRY.keys
            else
              hooks_config.split(",").map(&:strip)
            end

    installed = []
    names.each do |name|
      klass = HOOK_REGISTRY[name]
      next unless klass

      hook = klass.new(transport: transport, config: config)
      if hook.install
        installed << hook
      end
    rescue StandardError => e
      warn "[phantex] failed to install hook #{name}: #{e.message}" if config.debug
    end
    installed
  end
end
