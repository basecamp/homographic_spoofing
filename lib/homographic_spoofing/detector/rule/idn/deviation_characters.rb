# Four characters handled differently by IDNA 2003 and IDNA 2008. UTS46
# transitional processing treats them as IDNA 2003 does; maps U+00DF and
# U+03C2 and drops U+200[CD].
class HomographicSpoofing::Detector::Rule::Idn::DeviationCharacters < HomographicSpoofing::Detector::Rule::Idn::Base
  DEVIATION_CHARACTERS = %W[ ß ς \u200c \u200d ].to_set

  def attack_detected?
    (label_set & DEVIATION_CHARACTERS).present?
  end
end
