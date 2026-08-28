# Detects IDN Spoofing homographic attacks (See https://en.wikipedia.org/wiki/IDN_homograph_attack).
#
# The implementation follows Google Chrome IDN policy
# (See https://chromium.googlesource.com/chromium/src.git/+/master/docs/idn.md#google-chrome_s-idn-policy)
# but with some limitations:
#  - It doesn't rely on ICU4C uspoof.h (https://unicode-org.github.io/icu-docs/apidoc/released/icu4c/uspoof_8h.html)
#    hence the script confusable detection is not as precise.
#  - It doesn't implement 13. of Google IDN policy.
class HomographicSpoofing::Detector::Idn
  def self.detected?(domain)
    new(domain).detected?
  end

  def self.detections(domain)
    new(domain).detections
  end

  def initialize(domain)
    @original_domain = domain
    @domain = domain.downcase
  end

  def detected?
    detections.any?
  end

  def detections
    rules.select(&:attack_detected?).map do |rule|
      HomographicSpoofing::Detector::Detection.new(rule.reason, original_case(rule.label))
    end
  rescue PublicSuffix::Error
    # Invalid IDN is a spoof.
    [ HomographicSpoofing::Detector::Detection.new("invalid_domain", original_domain) ]
  end

  private
    attr_reader :domain, :original_domain

    # Detection runs on the lowercased domain, so labels come back lowercased.
    # Recover the original-cased run of the domain the label occupies, so the
    # sanitizer can substitute by exact match instead of regexp case folding —
    # which both over-matches (folds unrelated ASCII, e.g. ſ/s) and under-matches
    # (misses case pairs folding omits, e.g. Ⱥ/ⱥ). Map each lowercased position
    # back to the original character it came from, then locate the label in the
    # lowercased form. This stays correct — and linear — where a fixed offset
    # would not: when a character lowercases to a different length (İ → i̇), and
    # when PublicSuffix stripped surrounding characters the raw domain carries.
    def original_case(label)
      origin = []
      lowercased = +""
      original_domain.each_char.with_index do |char, index|
        downcased = char.downcase
        lowercased << downcased
        downcased.length.times { origin << index }
      end

      from = 0
      while (start = lowercased.index(label, from))
        span = original_domain[origin[start]..origin[start + label.length - 1]]
        # `index` can land inside a character whose lowercase spans several (İ →
        # i̇), so accept only a span that round-trips exactly to the label.
        return span if span.downcase == label
        from = start + 1
      end
      label
    end

    def rules
      @rules ||= contexts.flat_map { |ctx| rules_for(ctx) }
    end

    def rules_for(context)
      [
        HomographicSpoofing::Detector::Rule::DisallowedCharacters,
        HomographicSpoofing::Detector::Rule::MixedScripts,
        HomographicSpoofing::Detector::Rule::MixedDigits,
        HomographicSpoofing::Detector::Rule::Idn::InvisibleCharacters,
        HomographicSpoofing::Detector::Rule::Idn::UnsafeMiddleDot,
        HomographicSpoofing::Detector::Rule::Idn::ScriptConfusable,
        HomographicSpoofing::Detector::Rule::Idn::Digits,
        HomographicSpoofing::Detector::Rule::Idn::DangerousPattern,
        HomographicSpoofing::Detector::Rule::Idn::ScriptSpecific,
        HomographicSpoofing::Detector::Rule::Idn::DeviationCharacters
      ].map { |klass| klass.new(context) }
    end

    def contexts
      [ public_suffix.sld, public_suffix.trd ].compact.map do |label|
        HomographicSpoofing::Detector::Rule::Idn::Context.new(label: label, tld: public_suffix.tld)
      end
    end

    def public_suffix
      @public_suffix ||= icann_domain || non_icann_domain
    end

    def icann_domain
      PublicSuffix.parse(domain, ignore_private: true) if PublicSuffix.valid?(domain)
    end

    def non_icann_domain
      if PublicSuffix::List.default.find(domain, default: nil, ignore_private: true).present?
        PublicSuffix::Domain.new(domain)
      else
        raise PublicSuffix::DomainInvalid
      end
    end
end
