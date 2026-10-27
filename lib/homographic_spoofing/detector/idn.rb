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
      HomographicSpoofing::Detector::Detection.new(rule.reason, original_case(rule.label, rule.occurrence))
    end
  rescue PublicSuffix::Error
    # Invalid IDN is a spoof.
    [ HomographicSpoofing::Detector::Detection.new("invalid_domain", original_domain) ]
  end

  private
    attr_reader :domain, :original_domain

    # Detection runs on the lowercased domain, so labels come back lowercased.
    # Recover the original-cased spelling of the label at its own position, so
    # the sanitizer can substitute by exact match instead of regexp case folding,
    # which both over-matches (folds unrelated ASCII, e.g. ſ/s) and under-matches
    # (misses case pairs folding omits, e.g. Ⱥ/ⱥ). A label repeated in the domain
    # resolves to the casing of its own occurrence, counted left to right.
    def original_case(label, occurrence = 0)
      original_labels.fetch(label, [])[occurrence] || label
    end

    # Every whole label of the raw domain, in its original casing, grouped by its
    # lowercased form in left-to-right order. Labels are bounded by ".", never by
    # a match inside a longer sibling ("з" inside "магаЗин"), and keep any
    # whitespace inside them as PublicSuffix does; only the whitespace it strips
    # from the ends of the domain is set aside. Built in one pass, so resolving
    # every detection stays linear in the domain's length.
    def original_labels
      @original_labels ||= begin
        originals = original_domain.split(".", -1)
        originals[0] = originals[0].lstrip if originals.any?
        originals[-1] = originals[-1].rstrip if originals.any?
        originals.each_with_object({}) do |original, labels|
          (labels[original.downcase] ||= []) << original
        end
      end
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
      tld_allowances = {}
      labels.map do |label, occurrence|
        HomographicSpoofing::Detector::Rule::Idn::Context.new(label:, tld: registry_suffix, occurrence:, tld_allowances:)
      end
    end

    # Every label left of the registry suffix, split on the same dot the
    # renderer draws so each rule sees one real label rather than a chain. The
    # mixed-script, confusable and digit rules are per-label: a combined chain
    # both hides attacks (a benign sibling dilutes an all-look-alike label out of
    # detection) and invents them (two single-script sibling labels look "mixed"
    # together though each is safe on its own).
    #
    # Labels are kept in left-to-right domain order and paired with the index of
    # their occurrence among identical labels, so a repeated label recovers the
    # casing of its own position (see #original_case).
    def labels
      seen = Hash.new(0)
      split_domain.last.reject(&:empty?).map do |label|
        occurrence = seen[label]
        seen[label] += 1
        [ label, occurrence ]
      end
    end

    def registry_suffix
      split_domain.first
    end

    # Splits the domain into the suffix its registry controls and the labels to
    # its left. Unlike PublicSuffix.parse:
    #  - The label a wildcard entry matches (раураӏ in раураӏ.mm, under *.mm) is
    #    not fixed by the registry, so it is checked like any other label, and
    #    the registry suffix is only the part the entry spells out (mm).
    #  - A domain that is itself a public suffix (co.uk, mm) has no label to
    #    check, and is not an error.
    #  - Private entries (github.io, *.compute.amazonaws.com) are ignored, so
    #    names under them are checked like any other name.
    def split_domain
      @split_domain ||= begin
        name = PublicSuffix.normalize(domain)
        raise name if name.is_a?(PublicSuffix::DomainInvalid)

        rule = PublicSuffix::List.default.find(name, default: nil, ignore_private: true)
        # Unknown TLD: the default rule applies, and a single label is invalid.
        registry_suffix = rule ? rule.parts.join(".") : PublicSuffix.parse(name, ignore_private: true).tld
        left = name.delete_suffix(registry_suffix).delete_suffix(".")
        [ registry_suffix, left.split(".", -1) ]
      end
    end
end
