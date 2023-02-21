# 5. of Google Chrome IDN policy See http://www.unicode.org/reports/tr39/#highly_restrictive
class HomographicSpoofing::Detector::Rule::MixedScripts < HomographicSpoofing::Detector::Rule::Base
  def attack_detected?
    !highly_restrictive_scripts_combination?
  end

  private
    BOPO = "Bopomofo"
    HANG = "Hangul"
    HANI = "Han"
    HIRA = "Hiragana"
    KANA = "Katakana"
    LATN = "Latin"

    JAPANESE = Set[HANI, HIRA, KANA]
    CHINESE  = Set[BOPO, HANI]
    KOREAN   = Set[HANI, HANG]

    HIGHLY_RESTRICTIVE_SCRIPT_COMBINATIONS = [
      Set[*JAPANESE, LATN],
      Set[*CHINESE,  LATN],
      Set[*KOREAN,   LATN]
    ]

    def highly_restrictive_scripts_combination?
      scripts.length == 1 || HIGHLY_RESTRICTIVE_SCRIPT_COMBINATIONS.any? do |highly_restrictive_script_combination|
        scripts.subset?(highly_restrictive_script_combination)
      end
    end
end
