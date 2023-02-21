require_relative "lib/homographic_spoofing/version"

Gem::Specification.new do |spec|
  spec.name     = "homographic_spoofing"
  spec.version  = HomographicSpoofing::VERSION
  spec.authors  = ["Jacopo Beschi"]
  spec.email    = ["jacopo@37signals.com"]
  spec.homepage = "https://github.com/basecamp/homographic_spoofing"
  spec.summary  = "A toolkit to both detect and sanitize homographic spoofing attacks in URLs and Email addresses"
  spec.license  = "MIT"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.files = Dir["lib/**/*", "MIT-LICENSE", "README.md"]
end
