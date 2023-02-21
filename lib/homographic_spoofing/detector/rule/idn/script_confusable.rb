# 9. and 10. of Google Chrome IDN policy See http://unicode.org/reports/tr39/#Confusable_Detection
class HomographicSpoofing::Detector::Rule::Idn::ScriptConfusable < HomographicSpoofing::Detector::Rule::Idn::Base
  def attack_detected?
    SCRIPT_CONFUSABLES.any? do |confusable|
      confusable_chars = label.scan(confusable.script)
      confusable_chars.present? &&
        confusable_chars.all? { confusable.latin_lookalike.match?(_1) } &&
        !is_script_confusable_allowed_for_tld?(confusable)
    end
  end

  private
    Confusable = Struct.new(:script, :latin_lookalike, :allowed_tlds)
    SCRIPT_CONFUSABLES = [
      # Armenian
      [ /\p{armn}/, /[ագզէլհյոսւօՙ]/, /am/ ],
      # Cyrillic
      [ /\p{cyrl}/, /[аысԁеԍһіюјӏорԗԛѕԝхуъьҽпгѵѡ]/, /bg|by|kz|pyc|ru|su|ua|uz/ ],
      # # Ethiopic (Ge'ez).
      [ /\p{ethi}/, /[ሀሠሰስበነተከዐዕዘጠፐꬅ]/, /er|et/ ],
      # # Georgian
      [ /\p{geor}/, /[იოყძხჽჿ]/, /ge/ ],
      # # Greek
      [ /\p{grek}/, /[αικνρυωηοτ]/, /gr/ ],
      # # Hebrew
      [ /\p{hebr}/, /[דוחיןסװײ׳ﬦ]/, /il/ ],
      # # Bengali
      [ /\p{beng}/, /[০৭]/, nil ],
      # # Devanagari
      [ /\p{Deva}/, /[ऽ०ॱ]/, nil ],
      # # Gujarati
      [ /\p{Gujr}/, /[ડટ૦૧]/, nil ],
      # # Gurmukhi
      [ /\p{Guru}/, /[੦੧]/, nil ],
      # # Kannada
      [ /\p{Knda}/, /[ಽ೦೧]/, nil ],
      # # Malayalam
      [ /\p{Mlym}/, /[ടഠധനറ൦]/, nil ],
      # # Oriya
      [ /\p{Orya}/, /[ଠ୦୮]/, nil ],
      # # Tamil
      [ /\p{Taml}/, /[டப௦]/, nil ],
      # # Telugu
      [ /\p{Telu}/, /[౦౧]/, nil ],
      # # Myanmar
      [ /\p{Mymr}/, /[ခဂငထပဝ၀၂ၔၜ\u1090\u1091\u1095\u1096\u1097]/, /[a-z]+\.mm/ ],
      # # Thai
      [ /\p{Thai}/, /[ทนบพรหเแ๐ดลปฟม]/, /th/ ]
    ].map { Confusable.new(*_1) }

    def is_script_confusable_allowed_for_tld?(confusable)
      tld_contains_any_letter_from_script?(confusable.script) ||
        confusable.allowed_tlds&.match?(tld)
    end

    def tld_contains_any_letter_from_script?(script)
      script.match?(tld)
    end
end
