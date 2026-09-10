class HomographicSpoofing::Detector::Rule::Idn::Context < HomographicSpoofing::Detector::Rule::Context
  attr_reader :tld

  def initialize(label:, tld:, occurrence: 0)
    @tld = tld
    super(label:, occurrence:)
  end
end
