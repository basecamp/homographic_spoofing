# 7. of Google Chrome IDN policy
class HomographicSpoofing::Detector::Rule::Idn::InvisibleCharacters < HomographicSpoofing::Detector::Rule::Idn::Base
  def attack_detected?
    INVISIBLE_CHARACTERS_REGEXP.match?(label)
  end

  private
    INVISIBLE_CHARACTERS_REGEXP = Regexp.union(
      /\u0e48{2,}/,   # Thai tone repeated
      /\u0301{2,}/,   # accute accent repeated
      /\u00e1\u0301/, # 'a' with acuted accent + another acute accent
      /^\u0300/,      # Combining mark at the beginning
    )
end
