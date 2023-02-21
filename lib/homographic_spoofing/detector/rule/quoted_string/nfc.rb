# See http://www.unicode.org/reports/tr39/#Email_Security_Profiles nfc.
class HomographicSpoofing::Detector::Rule::QuotedString::Nfc < HomographicSpoofing::Detector::Rule::Base
  def attack_detected?
    !label.unicode_normalized?(:nfc)
  end
end
