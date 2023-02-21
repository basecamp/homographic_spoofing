# 12. of Google Chrome IDN policy
class HomographicSpoofing::Detector::Rule::Idn::DangerousPattern < HomographicSpoofing::Detector::Rule::Idn::Base
  DANGEROUS_PATTERNS = Regexp.union(
    /# Disallow the following as they may be mistaken for slashes when
    # they're surrounded by non-Japanese scripts (i.e. has non-Katakana
    # Hiragana or Han scripts on both sides):
    # "ノ" (Katakana no, U+30ce), "ソ" (Katakana so, U+30bd),
    # "ゾ" (Katakana zo, U+30be), "ン" (Katakana n, U+30f3),
    # "丶" (CJK unified ideograph, U+4E36),
    # "乀" (CJK unified ideograph, U+4E40),
    # "乁" (CJK unified ideograph, U+4E41),
    # "丿" (CJK unified ideograph, U+4E3F).
    # If {no, so, zo, n} next to a
    # non-Japanese script on either side is disallowed.
    [^\p{kana}\p{hira}\p{hani}]
    [\u30ce\u30f3\u30bd\u30be\u4e36\u4e40\u4e41\u4e3f]
    [^\p{kana}\p{hira}\p{hani}]/x,

      /# Disallow three Hiragana letters (U+307[8-A]) or Katakana letters
      # (U+30D[8-A]) that look exactly like each other when they're used
      # in a label otherwise entirely in Katakana or Hiragana.
      ^[\p{kana}]+[\u3078-\u307a][\p{kana}]+\z/x,
      /^[\p{hira}]+[\u30d8-\u30da][\p{hira}]+\z/,

      /# Disallow U+30FD (Katakana iteration mark) and U+30FE (Katakana
                                                               # voiced iteration mark) unless they're preceded by a Katakana.
        ([^\p{kana}][\u30fd\u30fe]|^[\u30fd\u30fe])/x,

        /# Disallow U+30FB (Katakana Middle Dot) and U+30FC (Hiragana-
                                                             # Katakana Prolonged Sound) used out-of-context.
          ([^\p{kana}\p{hira}]\u30fc|^\u30fc|[a-z]\u30fb|\u30fb[a-z])/x,

          /# Disallow these CJK ideographs if they are next to non-CJK
          # characters. These characters can be used to spoof Latin
          # characters or punctuation marks:
          # U+4E00 (一), U+3127 (ㄧ), U+4E28 (丨), U+4E5B (乛), U+4E03 (七),
          # U+4E05 (丅), U+5341 (十), U+3007 (〇), U+3112 (ㄒ), U+311A (ㄚ),
          # U+311F (ㄟ), U+3128 (ㄨ), U+3129 (ㄩ), U+3108 (ㄈ), U+31BA (ㆺ),
          # U+31B3 (ㆳ), U+5DE5 (工), U+31B2 (ㆲ), U+8BA0 (讠), U+4E01 (丁)
          # These characters are already blocked:
          # U+2F00 (⼀) (normalized to U+4E00), U+3192 (㆒), U+2F02 (⼂),
          # U+2F17 (⼗) and U+3038 (〸) (both normalized to U+5341 (十)).
          # Check if there is non-{Hiragana, Katagana, Han, Bopomofo} on the
          # left.
          [^\p{kana}\p{hira}\p{hani}\p{bopo}]
    [\u4e00\u3127\u4e28\u4e5b\u4e03\u4e05\u5341\u3007\u3112\u311a\u311f\u3128\u3129\u3108\u31ba\u31b3\u5dE5\u31b2\u8ba0\u4e01]/x,
      /# Check if there is non-{Hiragana, Katagana, Han, Bopomofo} on the
      # right.
      [\u4e00\u3127\u4e28\u4e5b\u4e03\u4e05\u5341\u3007\u3112\u311a\u311f\u3128\u3129\u3108\u31ba\u31b3\u5de5\u31b2\u8ba0\u4e01]
    [^\p{kana}\p{hira}\p{hani}\p{bopo}]/x,

      /# Disallow combining diacritical mark (U+0300-U+0339) after a
      # non-LGC character. Other combining diacritical marks are not in
      # the allowed character set.
      [^\p{latn}\p{grek}\p{cyrl}][\u0300-\u0339]/x,

      /# Disallow dotless i (U+0131) followed by a combining mark.
      \u0131[\u0300-\u0339]/x,

      /# Disallow combining Kana voiced sound marks.
      (\u3099|\u309a)/x,

      /# Disallow U+0307 (dot above) after 'i', 'j', 'l' or dotless i
      # (U+0131). Dotless j (U+0237) is not in the allowed set to begin
      # with.
      [ijl]\u0307/x,
      /^\u0237/
  )

  def attack_detected?
    DANGEROUS_PATTERNS.match?(label)
  end
end
