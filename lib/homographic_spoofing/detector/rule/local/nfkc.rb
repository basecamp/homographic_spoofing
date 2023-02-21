# See http://www.unicode.org/reports/tr39/#Email_Security_Profiles nkfc.
class HomographicSpoofing::Detector::Rule::Local::Nfkc < HomographicSpoofing::Detector::Rule::Base
  def attack_detected?
    !label.unicode_normalized?(:nfkc)
  end
end
