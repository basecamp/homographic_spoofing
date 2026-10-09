class HomographicSpoofing::Sanitizer::Base
  class_attribute :logger, default: HomographicSpoofing.logger

  def self.sanitize(field)
    new(field).sanitize
  end

  def initialize(field)
    @field = field
  end

  def sanitize
    result = field.dup
    # Longest label first: encoding a short label inside a longer detected one
    # (а inside а\u202e) would leave the longer one unmatched and unencoded.
    detector_class.new(field).detections.sort_by { -_1.label.length }.each do |detection|
      log(detection.reason, detection.label)
      result = punycode(result, detection.label)
    end
    result
  end

  private
    attr_reader :field

    def punycode(source, label)
      # A block, so a backslash in the label isn't read as a back-reference.
      replacement = Dnsruby::Name.punycode(label)
      source.gsub(label) { replacement }
    end

    def detector_class
      raise NotImplementedError, "subclasses must override this"
    end

    def log(reason, label)
      self.class.logger.info("#{spoofing_type} Spoofing detected for: \"#{reason}\" on: \"#{label}\".") if self.class.logger
    end

    def spoofing_type
      raise NotImplementedError, "subclasses must override this"
    end
end
