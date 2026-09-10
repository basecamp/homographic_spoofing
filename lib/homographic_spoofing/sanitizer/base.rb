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

    # Detections are per label. When the label is a complete component of the
    # field — a whole domain label or local part, delimited by "." or "@" —
    # punycode it as that component so an offending label is never replaced as a
    # substring of a benign sibling (e.g. the Cyrillic digit-look-alike "з" that
    # also sits inside "магазин"), and every occurrence is sanitized even when
    # the same spoof repeats in different casing across labels. Components are
    # matched with String#downcase, which — unlike regexp /i case folding — does
    # not over-match unrelated case pairs (ſ/s, ᴡ/W). A label that is only a
    # substring of a component (a display name carrying spaces) has no whole
    # component to match and falls back to the exact substring replacement.
    def punycode(source, label)
      key = label.downcase
      components = source.split(/([.@])/)
      if components.any? { |component| component_label?(component) && component.strip.downcase == key }
        components.map { |component| punycode_component(component, key) }.join
      else
        source.gsub(label) { Dnsruby::Name.punycode(label) }
      end
    end

    def punycode_component(component, key)
      content = component.strip
      component_label?(component) && content.downcase == key ? component.sub(content, Dnsruby::Name.punycode(content)) : component
    end

    def component_label?(component)
      component != "." && component != "@"
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
