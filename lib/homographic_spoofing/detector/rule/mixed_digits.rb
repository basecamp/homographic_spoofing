# 6. of Google Chrome IDN policy
class HomographicSpoofing::Detector::Rule::MixedDigits < HomographicSpoofing::Detector::Rule::Base
  def attack_detected?
    digits_scripts.many?
  end

  private
    def digits_scripts
      digits.map { digits_map[_1] }.uniq
    end

    def digits
      label.scan(/[[:digit:]]/)
    end

    def digits_map
      @@digits_map ||= build_digits_map
    end

    def build_digits_map
      CSV.parse(read_digits).each_with_object({}) do |(char, script), map|
        map[char] = script
      end
    end

    # Built with script/development/generate_digits_characters.rb
    def read_digits
      File.read("#{__dir__}/data/digits.csv")
    end
end
