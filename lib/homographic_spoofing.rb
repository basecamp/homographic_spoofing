require "zeitwerk"
require "unicode/scripts"
require "dnsruby"
require "public_suffix"
require "mail"
require "csv"
require "active_support"
require "active_support/core_ext"

loader = Zeitwerk::Loader.for_gem
loader.setup

module HomographicSpoofing
  mattr_accessor :logger, instance_accessor: false

  class << self
    def email_address_spoof?(email_address)
      HomographicSpoofing::Detector::EmailAddress.detected?(email_address)
    end

    def email_name_spoof?(email_address)
      HomographicSpoofing::Detector::QuotedString.detected?(email_address)
    end

    def email_local_spoof?(email_address)
      HomographicSpoofing::Detector::Local.detected?(email_address)
    end

    def idn_spoof?(idn)
      HomographicSpoofing::Detector::Idn.detected?(idn)
    end

    def sanitize_email_address(email_address)
      HomographicSpoofing::Sanitizer::EmailAddress.sanitize(email_address)
    end

    def sanitize_email_name(email_address)
      HomographicSpoofing::Sanitizer::QuotedString.sanitize(email_address)
    end

    def sanitize_idn(idn)
      HomographicSpoofing::Sanitizer::Idn.sanitize(idn)
    end
  end
end
