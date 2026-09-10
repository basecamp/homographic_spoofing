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
    detections = detector_class.new(field).detections
    detections.each { |detection| log(detection.reason, detection.label) }
    apply(result, detections)
  end

  private
    attr_reader :field

    # Punycode each offending label only within the component it came from. A
    # spanned detection carries the [offset, length] of its component, so a
    # domain-label spoof is confined to the domain and never rewrites a benign
    # local part that merely equals the same string — this is what keeps
    # "з@мир.з.example.com" punycoding the domain label "з" while leaving the "з"
    # mailbox intact. Spans are spliced back right-to-left so each edit leaves the
    # earlier offsets valid. A detection with no span (a bare IDN or quoted
    # string) spans the whole field and is applied last, over what remains.
    def apply(result, detections)
      whole, spanned = detections.partition { |detection| detection.span.nil? }
      spanned.group_by(&:span).sort_by { |(offset, _length), _group| -offset }.each do |(offset, length), group|
        segment = result[offset, length]
        result[offset, length] = group.map(&:label).inject(segment) { |text, label| replace_label(text, label) }
      end
      whole.inject(result) { |text, detection| replace_label(text, detection.label) }
    end

    # Replace `label` where it is a whole "."-delimited component of the region,
    # so an offending label is never rewritten as a substring of a benign sibling
    # (the Cyrillic digit-look-alike "з" that also sits inside "магазин"), and
    # every matching component is punycoded from its own spelling — case-exact,
    # so a spoof repeated in different casing is handled per occurrence. A label
    # that is only a substring of a component (a display name carrying spaces)
    # has no whole component to match and falls back to exact substring
    # replacement. The surrounding whitespace PublicSuffix strips is preserved.
    def replace_label(region, label)
      if region.split(".").any? { |component| component.strip == label }
        region.split(/(\.)/).map { |component| component.strip == label ? component.sub(label, Dnsruby::Name.punycode(label)) : component }.join
      else
        region.gsub(label) { Dnsruby::Name.punycode(label) }
      end
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
