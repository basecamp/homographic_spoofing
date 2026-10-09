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
    checked_labels.flat_map do |label, original_label|
      rules_for(context_for(label)).select(&:attack_detected?).map do |rule|
        HomographicSpoofing::Detector::Detection.new(rule.reason, original_label)
      end
    end
  rescue PublicSuffix::Error
    # Invalid IDN is a spoof.
    [ HomographicSpoofing::Detector::Detection.new("invalid_domain", original_domain) ]
  end

  private
    attr_reader :domain, :original_domain

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

    def context_for(label)
      HomographicSpoofing::Detector::Rule::Idn::Context.new(label: label, tld: registry_suffix)
    end

    # Each label to check, lowercased, paired with the same label as written in
    # the domain. Detection runs on the lowercased label; the sanitizer
    # substitutes the label as written, by exact match instead of regexp case
    # folding, which both over-matches (folds unrelated ASCII, e.g. ſ/s) and
    # under-matches (misses case pairs folding omits, e.g. Ⱥ/ⱥ). Labels are
    # paired by position, which holds when a character lowercases to a
    # different length (İ → i̇), and when the same label appears in two
    # casings (РАУРАӀ.раураӏ.mm). A label repeated verbatim is checked once.
    def checked_labels
      written = original_domain.strip.chomp(".").split(".", -1)
      labels.each_with_index.filter_map do |label, index|
        next if label.empty?
        original_label = written[index]
        [ label, original_label&.downcase == label ? original_label : label ]
      end.uniq
    end

    def registry_suffix
      split_domain.first
    end

    def labels
      split_domain.last
    end

    # Splits the domain into the suffix its registry controls and the labels to
    # its left, each checked on its own as Chrome does. Unlike PublicSuffix.parse:
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
