class HomographicSpoofing::Detector::Rule::Context
  attr_reader :label, :occurrence

  # `occurrence` disambiguates labels that repeat within a domain: it is the
  # zero-based index of this label among identical labels, in left-to-right
  # order, so the original casing of the right occurrence can be recovered.
  def initialize(label:, occurrence: 0)
    @label = label
    @occurrence = occurrence
  end

  SCRIPT_COMMON = "Common"
  SCRIPT_INHERITED = "Inherited"
  IGNORED_SCRIPTS = Set[SCRIPT_COMMON, SCRIPT_INHERITED]

  def scripts
    @scripts ||= Unicode::Scripts.scripts(label).to_set - IGNORED_SCRIPTS
  end

  def label_set
    @label_set ||= label.chars.to_set
  end
end
