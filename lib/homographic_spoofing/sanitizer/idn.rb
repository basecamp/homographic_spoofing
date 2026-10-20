class HomographicSpoofing::Sanitizer::Idn < HomographicSpoofing::Sanitizer::Base
  private
    def detector_class
      HomographicSpoofing::Detector::Idn
    end

    def spoofing_type
      "EmailIDN"
    end

    # The detector reports labels as PublicSuffix does: with the domain's own
    # leading and trailing padding set aside, but any whitespace inside the
    # domain kept on its label ("А " in " А .А .com"). Set the same padding
    # apart as components of its own, so each label component reads as its
    # label was reported.
    def split_components(source)
      components = super
      if components.empty?
        components
      else
        leading = components.first[/\A\s*/]
        components[0] = components.first.delete_prefix(leading)
        trailing = components.last[/\s*\z/]
        components[-1] = components.last.delete_suffix(trailing)
        [ leading, *components, trailing ].reject(&:empty?)
      end
    end
end
