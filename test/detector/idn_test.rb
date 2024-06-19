require "test_helper"

class HomographicSpoofing::Detector::IdnTest < ActiveSupport::TestCase
  test "Single script" do
    assert_safe("Aabcdef.com")        # Latin
    assert_safe("абгдеж.ru")          # Cyrillic
    assert_safe("αβγχψω.gr")          # Greek
    assert_safe("おかがキギク.co.jp") # Hiragana, Katakana
    assert_safe("ㄈㄉㄊ夕.cn")        # Bopomofo, Han
  end

  test "Valid mixed scripts" do
    assert_safe("おaかbがcキdギeクf.co.jp") # Latin, Hiragana, Katakana
    assert_safe("aㄉbㄊcde夕f.com")         # Latin, Bopomofo, Han
    assert_safe("example.বাংলা")            # Latin, Bengali
  end

  test "Invalid mixed scripts" do
    assert_attack("аaбbгcдdеeжf.ru")  # Cyrillic, Latin
    assert_attack("paypαl.com")       # Greek, Latin
    assert_attack("paypαl.test.com")  # Greek, Latin
    assert_attack("abc𐒊𐒋𐒌.com")       # Latin, Osmanya
    assert_attack("ㄈㄉㄊおかが.com") # Bopomofo, Hiragana
    assert_attack("ㄈㄉㄊᄊᄋᄌ.com") # Bopomofo, Hangul
    assert_attack("おかがᄊᄋᄌ.com") # Hangul, Hiragana
    assert_attack("ꓚꓛꓜᎪᎫᎬ.com")       # Cherokee, Lisu
    assert_attack("abꓚꓛᎪᎫ.com")       # Cherokee, Latin, Lisu
    assert_attack("αаβбγгχдψеωж.com") # Cyrillic, Greek
    assert_attack("ѕсоре.boom.com")   # Cyrillic, Latin
    assert_attack("раураӏ.com")       # Cyrillic, Latin
  end

  test "Unallowed characters" do
    assert_attack("g oogle.com")
    assert_attack("tᴡitter.com")
    assert_attack("clᴏudflare.com")
    assert_attack("ꔋ.com")
    assert_attack("ꮯꭺꭱꭰ.com")
    assert_attack("ϧ.com")
    assert_attack("ab♥.com")
    # Hyphens (http:#unicode.org/cldr/utility/confusables.jsp?a=-)
    assert_safe("abc-def.com")
    assert_attack("abc\u02d7def.com")
    assert_attack("abc\u2010def.com")
  end

  test "Latin spoof" do
    # ѕсоре.com with ѕсоре in Cyrillic.
    assert_attack("ѕсоре.com")
    # ѕсоре123.com with ѕсоре in Cyrillic.
    assert_attack("ѕсоре123.com")
    # ѕсоре-рау.com with ѕсоре and рау in Cyrillic.
    assert_attack("ѕсоре-рау.com")
    # ѕсоре1рау.com with scope and pay in Cyrillic and a non-letter between them.
    assert_attack("ѕсоре1рау.com")
    # музей (museum in Russian) has characters without a Latin-look-alike.
    assert_safe("музей.com")
    # ѕсоԗе.com is Cyrillic with Latin lookalikes.
    assert_attack("ѕсоԗе.com")
  end

  test "Mixed digits" do
    # 1\u{1D7E4}3rf with Mathematical sans-serif digit two
    assert_attack("1𝟤3rf.com", reason: "mixed_digits")
    # 123rf with Basic latin digits
    assert_safe("123rf.com")
  end

  test "Digits and digit spoofs" do
    # mixed numeric + numeric lookalike (12.com, using U+0577).
    assert_attack("1շ.com")
    # mixed numeric lookalike + numeric (੨0.com, uses U+0A68).
    assert_attack("੨0.com")
    # fully numeric lookalikes (৪੨.com using U+09EA and U+0A68).
    assert_attack("৪੨.com")
    # single script digit lookalikes (using three U+0A68 characters).
    assert_attack("੨੨੨.com")
    # Digit lookalike check of 16კ.com with character “კ” (U+10D9)
    assert_attack("16კ.com")
  end

  test "Icelandic spoof" do
    assert_attack("aþcdef.com")
    assert_safe("aþcdef.is")
    assert_attack("mnðpqr.com")
    assert_safe("mnðpqr.is")
  end

  test "Azerbaijan spoof" do
    assert_attack("əxample.com")
    assert_safe("əxample.az")
  end

  test "Latin middle dot spoof" do
    assert_attack("google·com.com")
    assert_attack("l·l.com")
    assert_safe("l·l.cat")
    assert_attack("a·l.cat")
    assert_attack("l·a.cat")
    assert_attack("·l.cat")
    assert_attack("l·.cat")
  end

  test "Deviation characters" do
    assert_attack("fuß.de")
    assert_attack("αβς.gr")
    # U+200C(ZWNJ)
    assert_attack("\u0924\u094d\u200c\u0930\u093f.in")
    # U+200C(ZWJ)
    assert_attack("\u0915\u094d\u200d.in")
  end

  test "Dangerous patterns" do
    # i followed by U+0307 (combining dot above)
    assert_attack("pi\u0307xel.com")
    # U+0131 (dotless i) followed by U+0307
    assert_attack("p\u0131\u0307xel.com")
    # j followed by U+0307 (combining dot above)
    assert_attack("j\u0307ack.com")
    # l followed by U+0307
    assert_attack("l\u0307ace.com")
    # Two Katakana-Hiragana combining mark in a row
    assert_attack("google.com\u309a\u309a.co.jp")
    # Do not allow a combining mark after dotless i/j.
    assert_attack("p\u0131\u0300xel.com")
    assert_attack("\u0237\u0301ack.com")
    ## U+30FC should be preceded by a Hiragana/Katakana.
    ## Katakana + U+30FC + Han
    assert_safe("\u30ab\u30fc\u91ce\u7403.jp")
    ## Hiragana + U+30FC + Han
    assert_safe("\u304b\u30fc\u91ce\u7403.jp")
    ## U+30FC + Han
    assert_attack("\u30fc\u52d5\u753b\u30fc.com")
    ## Han + U+30FC + Han
    assert_attack("\u65e5\u672c\u30fc\u91ce\u7403.jp")
    ## U+30FC at the beginning
    assert_attack("\u30fc\u65e5\u672c.jp")
    ## Latin + U+30FC + Latin
    assert_attack("abc\u30fcdef.jp")
    ## U+30FB (・) is not allowed next to Latin, but allowed otherwise.
    ## U+30FB + Han
    assert_safe("\u30fb\u91ce.jp")
    ## Han + U+30FB + Han
    assert_safe("\u65e5\u672c\u30fb\u91ce\u7403.jp")
    ## Latin + U+30FB + Latin
    assert_attack("abc\u30fbdef.jp")
    ## U+30FB + Latin
    assert_attack("\u30fbabc.jp")
    ## U+30FD (ヽ) is allowed only after Katakana.
    ## Katakana + U+30FD
    assert_safe("\u30ab\u30fd.jp")
    ## Hiragana + U+30FD
    assert_attack("\u304b\u30fd.jp")
    ## Han + U+30FD
    assert_attack("\u4e00\u30fd.jp")
    ## U+30FE (ヾ) is allowed only after Katakana.
    ## Katakana + U+30FE
    assert_safe("\u30ab\u30fe.jp")
    ## Hiragana + U+30FE
    assert_attack("\u304b\u30fe.jp")
    ## Han + U+30FE
    assert_attack("\u4e00\u30fe.jp")
    ## Combining Diacritic marks after a script other than Latin-Greek-Cyrillic
    # 한́글.com
    assert_attack("\ud55c\u0307\uae00.com")
    # 漢̇字.com
    assert_attack("\u6f22\u0307\u5b57.com")
    # नागरी́.com
    assert_attack("\u0928\u093e\u0917\u0930\u0940\u0301.com")
    ## U+4E00 and U+3127 should be blocked when next to non-CJK.
    assert_attack("ip\u4e00address.com")
    assert_attack("ip\u3127address.com")
    ## U+4E00 and U+3127 at the beginning and end of a string.
    assert_attack("google\u3127.com")
    assert_attack("\u3127google.com")
    ## These are allowed because U+4E00 and U+3127 are not immediately next to
    ## non-CJK.
    assert_safe("\u4e00\u751fgamer.com")
    ## U+4E00 with another ideograph.
    assert_safe("\u4e00\u4e01.com")
    ## CJK ideographs looking like slashes should be blocked when next to
    ## non-CJK.
    assert_attack("test\u4e36test.com")
    ## This is allowed because the ideographs are not immediately next to
    ## non-CJK.
    assert_safe("\u4e36\u4e40\u4e41\u4e3f.com")
    ## Kana voiced sound marks are not allowed.
    assert_attack("google\u3099.com")
    assert_attack("google\u309A.com")
  end

  test "Invisible characters" do
    # Thai tone mark malek(U+0E48) repeated
    assert_attack("\u0e23\u0e35\u0e48\u0e48.th")
    # Accute accent repeated
    assert_attack("a\u0301\u0301.com")
    # 'a' with acuted accent + another acute accent
    assert_attack("\u00e1\u0301.com")
    # Combining mark at the beginning
    assert_attack("\u0300abc.jp")
  end

  test "Whole script confusable" do
    # Armenian
    assert_attack("ոսւօ.com")
    assert_safe("ոսւօ.am")
    assert_safe("ոսւօ.հայ")
    # Ethiopic
    assert_attack("ሠዐዐፐ.com")
    assert_safe("ሠዐዐፐ.et")
    assert_safe("ሠዐዐፐ.ኢትዮጵያ")
    # Greek
    assert_attack("ικα.com")
    assert_safe("ικα.gr")
    assert_safe("ικα.ελ")
    # Georgian
    assert_attack("ჽჿხ.com")
    assert_safe("ჽჿხ.ge")
    assert_safe("ჽჿხ.გე")
    ## Hebrew
    assert_attack("חסד.com")
    assert_safe("חסד.il")
    assert_safe("קום.חסד")
    ## Myanmar
    assert_attack("င၀ဂခဂ.com")
    assert_safe("င၀ဂခဂ.net.mm")
    assert_safe("င၀ဂခဂ.မြန်မာ")
    ## Myanmar Shan digits
    assert_attack("႐႑႕႖႗.com")
    assert_safe("႐႑႕႖႗.net.mm")
    assert_safe("႐႑႕႖႗.မြန်မာ")
    ## Thai
    assert_attack("ทนบพรห.com")
    assert_safe("ทนบพรห.th")
    assert_safe("ทนบพรห.ไทย")
    assert_attack("พบเ๐.com")
    assert_safe("พบเ๐.th")
    assert_safe("พบเ๐.ไทย")
    ## Indic scripts:
    ## Bengali
    assert_attack("০৭০৭.com")
    ## Devanagari
    assert_attack("ऽ०ऽ.com")
    ## Gujarati
    assert_attack("ડટ.com")
    ## Gurmukhi
    assert_attack("੦੧੦੧.com")
    ## Kannada
    assert_attack("ಽ೦ಽ೧.com")
    ## Malayalam
    assert_attack("ടഠധ.com")
    ## Oriya
    assert_attack("୮ଠ୮ଠ.com")
    ## Tamil
    assert_attack("டபடப.com")
    ## Telugu
    assert_attack("౧౦౧౦౧౦.com")
  end

  test "Mixed script confusable" do
    # google with Armenian Small Letter Oh(U+0585)
    assert_attack("gօogle.com")
    assert_attack("օrange.com")
    assert_attack("cuckoօ.com")
    assert_attack("ძ4000.com")
  end

  test "PublixSuffix parsing errors" do
    assert_attack("  ", reason: "invalid_domain")
    assert_attack("example|.com", reason: "disallowed_characters")
  end

  private
    def assert_attack(domain, reason: nil)
      assert HomographicSpoofing::Detector::Idn.detected?(domain), "No Attack detected for #{domain}."
      if reason
        detections = HomographicSpoofing::Detector::Idn.detections(domain)
        assert_includes detections.map(&:reason), reason
      end
    end

    def assert_safe(domain)
      assert_not HomographicSpoofing::Detector::Idn.detected?(domain), "Attack detected for #{domain}."
    end
end
