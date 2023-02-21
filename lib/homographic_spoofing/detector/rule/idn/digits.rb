# 11. of Google Chrome IDN policy
class HomographicSpoofing::Detector::Rule::Idn::Digits < HomographicSpoofing::Detector::Rule::Idn::Base
  def attack_detected?
    contains_digit_lookalike? && contains_only_digits_or_digit_lookalike?
  end

  private
    def contains_digit_lookalike?
      label.chars.any? { |char| digit_lookalike?(char) }
    end

    def contains_only_digits_or_digit_lookalike?
      label.chars.all? { |char| digit?(char) || digit_lookalike?(char) }
    end

    def digit?(char)
      /[0-9]/.match?(char)
    end

    DIGIT_LOOKALIKES = %w[ θ २ ২ ੨ ੨ ૨ ೩ ೭ շ з ҙ ӡ उ ও ਤ ੩ ૩ ౩ ဒ ვ პ ੜ კ ੫ 丩 ㄐ ճ ৪ ੪ ୫ ૭ ୨ ౨ ].to_set

    def digit_lookalike?(char)
      DIGIT_LOOKALIKES.include?(char)
    end
end
