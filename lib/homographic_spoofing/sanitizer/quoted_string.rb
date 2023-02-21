class HomographicSpoofing::Sanitizer::QuotedString < HomographicSpoofing::Sanitizer::Base
  private
    def detector_class
      HomographicSpoofing::Detector::QuotedString
    end

    def spoofing_type
      "EmailQuotedString"
    end
end
