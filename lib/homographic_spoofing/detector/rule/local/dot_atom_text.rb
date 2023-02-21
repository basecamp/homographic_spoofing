# See http://www.unicode.org/reports/tr39/#Email_Security_Profiles dot-atom-text.
class HomographicSpoofing::Detector::Rule::Local::DotAtomText < HomographicSpoofing::Detector::Rule::Base
  def attack_detected?
    if invalid_dot_sequence?
      true
    elsif label_no_dots.present?
      !valid_start_sequence? || contains_invalid_char?
    end
  end

  private
    def invalid_dot_sequence?
      label.starts_with?(".") || label.ends_with?(".") || multiple_dots?
    end

    def multiple_dots?
      /\.{2,}/.match?(label)
    end

    def label_no_dots
      @label_no_dots ||= label.tr(".", "")
    end

    XID_Start_REGEXP = /\p{XIDS}/

    def valid_start_sequence?
      start = label.first
      simple_char?(start) || XID_Start_REGEXP.match?(start)
    end

    def contains_invalid_char?
      label_no_dots.chars.any? { invalid_char?(_1) }
    end

    # https://tools.ietf.org/html/rfc5322#section-3.2.3 atext
    ATEXT_REGEXP = %r{[!#-'*+\-/-9=?A-Z\^-~]}

    def invalid_char?(c)
      if simple_char?(c)
        !ATEXT_REGEXP.match(c)
      else
        HomographicSpoofing::Detector::Rule::DisallowedCharacters.allowed_chars_set.exclude?(c)
      end
    end

    def simple_char?(c)
      c < "\u007f"
    end
end
