class HomographicSpoofing::Detector::Rule::Context
  attr_reader :label

  def initialize(label:)
    @label = label
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
