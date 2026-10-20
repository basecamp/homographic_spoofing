class HomographicSpoofing::Sanitizer::Idn < HomographicSpoofing::Sanitizer::Base
  private
    def detector_class
      HomographicSpoofing::Detector::Idn
    end

    def spoofing_type
      "EmailIDN"
    end

    # A bare domain has no comments or quoted strings: the detector splits it on
    # every ".", so split it the same way. Honouring "(" or '"' here would let an
    # unmatched one fold the rest of the domain into one component, and every
    # detected label would then fall back to a substitution over the whole field.
    def label_components(region)
      region.split(/(\.)/, -1).map do |text|
        if text == "."
          Component.new(text, nil, 0)
        else
          Component.new(text, text.strip, text.index(/\S/) || 0)
        end
      end
    end
end
