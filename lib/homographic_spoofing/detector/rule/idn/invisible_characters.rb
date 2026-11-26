# 7. of Google Chrome IDN policy
class HomographicSpoofing::Detector::Rule::Idn::InvisibleCharacters < HomographicSpoofing::Detector::Rule::Idn::Base
  def attack_detected?
    COMBINING_MARK_AT_START.match?(label) || LONG_MARK_RUN.match?(label) || repeated_nonspacing_mark?
  end

  private
    COMBINING_MARK_AT_START = /\A\p{M}/

    # More marks in a row than UAX #15's Stream-Safe Text Format allows (30).
    # Checked before decomposing, which on some Rubies takes time quadratic in
    # the length of a run of marks.
    LONG_MARK_RUN = /\p{M}{31,}/

    # Decomposed first, so a precomposed letter followed by its own mark, such
    # as "é" + U+0301, counts as the mark repeated.
    def repeated_nonspacing_mark?
      !label.ascii_only? && label.unicode_normalize(:nfd).scan(/\p{Mn}+/).any? { |marks| marks.chars.uniq.size < marks.size }
    end
end
