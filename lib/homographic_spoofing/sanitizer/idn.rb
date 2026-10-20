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
    #
    # The detector reports labels as PublicSuffix does: with the domain's own
    # leading and trailing padding set aside, but any whitespace inside the
    # domain kept on its label ("А " in " А .А .com"). That padding is set apart
    # as components with no label, so each label component reads as its label
    # was reported.
    def label_components(region)
      core = region.strip
      leading = core.empty? ? region : region[0, region.index(core)]
      trailing = region[(leading.length + core.length)..]

      [ padding(leading), *core.split(/(\.)/, -1).map { |text| component(text) }, padding(trailing) ].compact
    end

    def component(text)
      if text == "."
        Component.new(text, nil, 0)
      else
        Component.new(text, text.strip, text.index(/\S/) || 0)
      end
    end

    def padding(text)
      Component.new(text, nil, 0) unless text.empty?
    end
end
