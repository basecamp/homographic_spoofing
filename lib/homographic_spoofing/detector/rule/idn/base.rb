class HomographicSpoofing::Detector::Rule::Idn::Base < HomographicSpoofing::Detector::Rule::Base
  delegate :tld, :tld_allowances, to: :@context
end
