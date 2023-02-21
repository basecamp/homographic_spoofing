# See http://www.unicode.org/reports/tr39/#Email_Security_Profiles bidicontrol.
class HomographicSpoofing::Detector::Rule::QuotedString::BidiControl < HomographicSpoofing::Detector::Rule::Base
  # See https://util.unicode.org/UnicodeJsps/list-unicodeset.jsp?a=%5B%3Abidicontrol%3A%5D&c=on&g=&i=
  # for the full list of bidirectional format characters.
  DISALLOWED_REGEXP = /[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]/

  def attack_detected?
    DISALLOWED_REGEXP.match?(label)
  end
end
