class HomographicSpoofing::Sanitizer::EmailAddress < HomographicSpoofing::Sanitizer::Base
   private
    def detector_class
      HomographicSpoofing::Detector::EmailAddress
    end

    def spoofing_type
      "EmailAddress"
    end
end
