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
      registry_suffix, labels = split_domain
      labels.map do |label|
        HomographicSpoofing::Detector::Rule::Idn::Context.new(label: label, tld: registry_suffix)
      end
    end

    # Splits the domain into the suffix its registry controls and the labels to
    # check, the way PublicSuffix.parse splits it into tld, sld and trd, except:
    #  - The label a wildcard entry matches (раураӏ in раураӏ.mm, under *.mm) is
    #    not fixed by the registry, so it is checked like any other label, and
    #    the registry suffix is only the part the entry spells out (mm).
    #  - A domain that is itself a public suffix (co.uk, mm) has no label to
    #    check, and is not an error.
    #  - Private entries (github.io, *.compute.amazonaws.com) are ignored, so
    #    names under them are checked like any other name.
    def split_domain
      name = PublicSuffix.normalize(domain)
      raise name if name.is_a?(PublicSuffix::DomainInvalid)

      case rule = PublicSuffix::List.default.find(name, default: nil, ignore_private: true)
      when nil
        # Unknown TLD: the default rule applies, and a single label is invalid.
        parsed = PublicSuffix.parse(name, ignore_private: true)
        [ parsed.tld, [ parsed.sld, parsed.trd ].compact ]
      when PublicSuffix::Rule::Wildcard
        left, _ = PublicSuffix::Rule::Normal.new(value: rule.value).decompose(name)
        *rest, wildcard_label = left.to_s.split(".")
        [ rule.value, [ *sld_and_trd(rest.join(".")), wildcard_label ].compact ]
      else
        left, registry_suffix = rule.decompose(name)
        [ registry_suffix || name, sld_and_trd(left.to_s) ]
      end
    end

    def sld_and_trd(left)
      *trd, sld = left.split(".")
      [ sld, trd.join(".").presence ].compact
    end
end
