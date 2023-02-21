class HomographicSpoofing::Detector::Rule::Idn::Base < HomographicSpoofing::Detector::Rule::Base
  delegate :tld, to: :@context
end
