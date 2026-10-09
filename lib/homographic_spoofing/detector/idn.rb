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
    # lowercased form in left-to-right order. Labels are bounded by "." with the
    # surrounding whitespace PublicSuffix strips from the raw domain set aside,
    # never by a match inside a longer sibling ("з" inside "магаЗин"). Built in
    # one pass, so resolving every detection stays linear in the domain's length.
    def original_labels
      @original_labels ||= original_domain.split(".").each_with_object({}) do |original, labels|
        (labels[original.strip.downcase] ||= []) << original.strip
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
      labels.map do |label, occurrence|
        HomographicSpoofing::Detector::Rule::Idn::Context.new(label:, tld: public_suffix.tld, occurrence:)
      end
    end

    # `trd` is the full subdomain chain ("a.b" in a.b.example.com). Split it on
    # the same dot the renderer draws so each rule sees one real label rather
    # than a chain. The mixed-script, confusable and digit rules are per-label:
    # a combined chain both hides attacks (a benign sibling dilutes an
    # all-look-alike label out of detection) and invents them (two single-script
    # sibling labels look "mixed" together though each is safe on its own).
    #
    # Labels are kept in left-to-right domain order and paired with the index of
    # their occurrence among identical labels, so a repeated label recovers the
    # casing of its own position (see #original_case).
    def labels
      ordered = [ *public_suffix.trd&.split("."), public_suffix.sld ].compact.reject(&:empty?)
      seen = Hash.new(0)
      ordered.map do |label|
        occurrence = seen[label]
        seen[label] += 1
        [ label, occurrence ]
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
