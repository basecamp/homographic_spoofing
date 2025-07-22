require_relative "lib/homographic_spoofing/version"

Gem::Specification.new do |spec|
  spec.name     = "homographic_spoofing"
  spec.version  = HomographicSpoofing::VERSION
  spec.authors  = ["Jacopo Beschi"]
  spec.email    = ["jacopo@37signals.com"]

  spec.summary  = "A toolkit to both detect and sanitize homographic spoofing attacks in URLs and Email addresses"

  spec.homepage = "https://github.com/basecamp/homographic_spoofing"
  spec.license  = "MIT"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.required_ruby_version = '>= 3.1.0'

  spec.files = Dir["lib/**/*", "MIT-LICENSE", "README.md"]


  spec.add_dependency "zeitwerk", "~> 2.5"
  spec.add_dependency "unicode-scripts"
  spec.add_dependency "dnsruby"
  spec.add_dependency "public_suffix"
  spec.add_dependency "mail"
  spec.add_dependency "activesupport"
  spec.add_dependency "csv", "~> 3.3"
end
