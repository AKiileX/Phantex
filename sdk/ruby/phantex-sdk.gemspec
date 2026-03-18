# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = "phantex-sdk"
  spec.version       = "0.1.0"
  spec.authors       = ["Phantex"]
  spec.email         = ["starxsec@proton.me"]

  spec.summary       = "Phantex Runtime Security SDK for Ruby"
  spec.description   = "Instrument Ruby AI agent frameworks with Phantex — " \
                        "captures tool calls, ships telemetry to the gateway, " \
                        "and hooks into ruby-openai and langchainrb."
  spec.homepage      = "https://github.com/AKiileX/Phantex"
  spec.license       = "Apache-2.0"
  spec.required_ruby_version = ">= 3.1.0"

  spec.files         = Dir["lib/**/*.rb", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]

  # Zero hard dependencies — frameworks are optional
  spec.metadata = {
    "homepage_uri"    => spec.homepage,
    "source_code_uri" => "https://github.com/AKiileX/Phantex/tree/main/sdk/ruby",
    "bug_tracker_uri" => "https://github.com/AKiileX/Phantex/issues",
  }
end
