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
    detector_class.new(field).detections.each do |detection|
      log(detection.reason, detection.label)
      result = punycode(result, detection.label)
    end
    result
  end

  private
    attr_reader :field

    # Substitutes whole occurrences only, so a detected label isn't encoded
    # inside a longer one that merely contains it (а inside академия).
    def punycode(source, label)
      source.gsub(/(?<![\p{L}\p{M}\p{N}_-])#{Regexp.escape(label)}(?![\p{L}\p{M}\p{N}_-])/) { Dnsruby::Name.punycode(label) }
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
