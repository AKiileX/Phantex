# frozen_string_literal: true

require_relative "phantex/version"
require_relative "phantex/config"
require_relative "phantex/context"
require_relative "phantex/events"
require_relative "phantex/transport"
require_relative "phantex/hooks"
require_relative "phantex/client"

module Phantex
  class Error < StandardError; end

  # Module-level convenience: start with defaults.
  #   require 'phantex'
  #   Phantex.start!
  def self.start!(config: nil)
    @client = Client.new(config: config || Config.from_env)
    @client.start
    @client
  end

  def self.stop!
    @client&.stop
    @client = nil
  end

  def self.client
    @client
  end
end
