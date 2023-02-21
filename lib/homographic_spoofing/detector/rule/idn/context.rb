class HomographicSpoofing::Detector::Rule::Idn::Context < HomographicSpoofing::Detector::Rule::Context
  attr_reader :tld

  def initialize(label:, tld:)
    @tld = tld
    super(label:)
  end
end
