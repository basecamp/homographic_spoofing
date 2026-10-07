require "test_helper"

class HomographicSpoofing::Detector::LocalTest < ActiveSupport::TestCase
  test "Single script" do
    assert_safe("Aabcdef")      # Latin
    assert_safe("абгдеж")       # Cyrillic
    assert_safe("αβγχψω")       # Greek
    assert_safe("おかがキギク") # Hiragana, Katakana
    assert_safe("ㄈㄉㄊ夕")     # Bopomofo, Han
  end

  test "Valid mixed scripts" do
    assert_safe("おaかbがcキdギeクf") # Latin, Hiragana, Katakana
    assert_safe("aㄉbㄊcde夕f")       # Latin, Bopomofo, Han
  end

  test "Invalid mixed scripts" do
    assert_attack("аaбbгcдdеeжf") # Cyrillic, Latin
    assert_attack("paypαl")       # Greek, Latin
    assert_attack("abc𐒊𐒋𐒌")       # Latin, Osmanya
    assert_attack("ㄈㄉㄊおかが") # Bopomofo, Hiragana
    assert_attack("ㄈㄉㄊᄊᄋᄌ") # Bopomofo, Hangul
    assert_attack("おかがᄊᄋᄌ") # Hangul, Hiragana
    assert_attack("ꓚꓛꓜᎪᎫᎬ")       # Cherokee, Lisu
    assert_attack("abꓚꓛᎪᎫ")       # Cherokee, Latin, Lisu
    assert_attack("αаβбγгχдψеωж") # Cyrillic, Greek
    assert_attack("ѕсоре.boom")   # Cyrillic, Latin
  end

  test "Quotation-mark look-alikes" do
    # The local part follows the same allowed set as domain labels (UTS #39 email
    # security profile), so a look-alike for the ASCII apostrophe is flagged here too.
    assert_safe("o'brien")
    assert_attack("o\u2019brien")
    assert_attack("o\u02bcbrien")
    assert_attack("o\u02bbbrien")
  end

  test "Mixed digits" do
    # 1\u{1D7E4}3rf with Mathematical sans-serif digit two
    assert_attack("1𝟤3rf", reason: "mixed_digits")
    # 123rf with Basic latin digits
    assert_safe("123rf")
  end

  test "Unicode NFKC format" do
    # Invalid unicode
    assert_attack("text".encode("ISO-8859-1"), reason: "invalid_unicode")
    assert_attack("1𝟤3rf".unicode_normalize(:nfc), reason: "nfkc")
    assert_safe("scope")
  end

  test "Dot atom text" do
    # Invalid atext
    assert_attack("1.\u001f", reason: "dot_atom_text")
    # Leading dot
    assert_attack(".123",     reason: "dot_atom_text")
    # Trailing dot
    assert_attack("123.",     reason: "dot_atom_text")
    # Multiple dots
    assert_attack("1..23",    reason: "dot_atom_text")
    assert_safe("1.2.Rf")
  end

  private
    def assert_attack(label, reason: nil)
      assert HomographicSpoofing::Detector::Local.detected?(label), "No Attack detected for #{label}."
      if reason
        detections = HomographicSpoofing::Detector::Local.detections(label)
        assert_includes detections.map(&:reason), reason
      end
    end

    def assert_safe(label)
      assert_not HomographicSpoofing::Detector::Local.detected?(label), "Attack detected for #{label}."
    end
end
