class HomographicSpoofing::Sanitizer::Idn < HomographicSpoofing::Sanitizer::Base
  private
    def detector_class
      HomographicSpoofing::Detector::Idn
    end

    def spoofing_type
      "EmailIDN"
    end
end
