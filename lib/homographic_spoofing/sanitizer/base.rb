class HomographicSpoofing::Sanitizer::Base
  class_attribute :logger, default: HomographicSpoofing.logger

  def self.sanitize(field)
    new(field).sanitize
  end

  def initialize(field)
    @field = field
  end

  def sanitize
    detections = detector_class.new(field).detections
    detections.each { |detection| log(detection.reason, detection.label) }
    punycode(field.dup, detections.map(&:label).uniq)
  end

  private
    attr_reader :field

    # Detections are per label. When a label is a complete component of the
    # field (a whole domain label or local part, delimited by "." or "@"),
    # punycode it as that component so an offending label is never replaced as a
    # substring of a benign sibling (e.g. the Cyrillic digit-look-alike "з" that
    # also sits inside "магазин"). Matching is case-exact: the detector reports
    # each label in the casing of its own position, so a spoof repeated in
    # different casing yields a detection per occurrence, and a benign
    # case-variant on the other side of the "@" is left alone. A label that is
    # only a substring of a component (a display name carrying spaces) has no
    # whole component to match and falls back to the exact substring replacement.
    #
    # The field is split once for all labels, so a domain with many offending
    # labels is sanitized in time linear in its length.
    def punycode(source, labels)
      components = source.split(/([.@])/)
      present = components.to_set(&:strip) | components
      whole, partial = labels.partition { |label| present.include?(label) }
      whole = whole.to_set

      result = components.map do |component|
        if whole.include?(component)
          Dnsruby::Name.punycode(component)
        elsif whole.include?(component.strip)
          punycode_component(component)
        else
          component
        end
      end.join
      partial.inject(result) { |text, label| text.gsub(label) { Dnsruby::Name.punycode(label) } }
    end

    def punycode_component(component)
      label = component.strip
      component.sub(label) { Dnsruby::Name.punycode(label) }
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
