# 3. and 4. of Google Chrome IDN policy See https://util.unicode.org/UnicodeJsps/list-unicodeset.jsp?a=%5B%3AIdentifierStatus%3DAllowed%3A&abb=on&g=&i=
class HomographicSpoofing::Detector::Rule::DisallowedCharacters < HomographicSpoofing::Detector::Rule::Base
  class << self
    # See http://kb.mozillazine.org/Network.IDN.blacklist_chars
    MOZILLA_DISALLOWED_CHARACTERS = Set[
      "\u0020", # Space
      "\u00a0", # No-break space
      "\u00bc", # Vulgar fraction one quarter
      "\u00bd", # Vulgar fraction one half
      "\u00be", # Vulgar fraction three quarters
      "\u01c3", # Latin letter retroflex click
      "\u02d0", # Modifier letter triangular colon
      "\u0337", # Combining short solidus overlay
      "\u0338", # Combining long solidus overlay
      "\u0589", # Armenian full stop
      "\u058a", # Armenian hyphen
      "\u05c3", # Hebrew punctuation sof pasuq
      "\u05f4", # Hebrew punctuation gershayim
      "\u0609", # Arabic-indic per mille sign
      "\u060a", # Arabic-indic per ten thousand sign
      "\u066a", # Arabic percent sign
      "\u06d4", # Arabic full stop
      "\u0701", # Syriac supralinear full stop
      "\u0702", # Syriac sublinear full stop
      "\u0703", # Syriac supralinear colon
      "\u0704", # Syriac sublinear colon
      "\u115f", # Hangul choseong filler
      "\u1160", # Hangul jungseong filler
      "\u1735", # Philippine single punctuation
      "\u2000", # En quad
      "\u2001", # Em quad
      "\u2002", # En space
      "\u2003", # Em space
      "\u2004", # Three-per-em space
      "\u2005", # Four-per-em space
      "\u2006", # Six-per-em-space
      "\u2007", # Figure space
      "\u2008", # Punctuation space
      "\u2009", # Thin space
      "\u200a", # Hair space
      "\u200b", # Zero width space
      "\u200e", # Left-to-right mark
      "\u200f", # Right-to-left mark
      "\u2010", # Hyphen
      "\u2019", # Right single quotation mark
      "\u2024", # One dot leader
      "\u2027", # Hyphenation point
      "\u2028", # Line separator
      "\u2029", # Paragraph separator
      "\u202a", # Left-to-right embedding
      "\u202b", # Right-to-left embedding
      "\u202c", # Pop directional formatting
      "\u202d", # Left-to-right override
      "\u202e", # Right-to-left override
      "\u202f", # Narrow no-break space
      "\u2039", # Single left-pointing angle quotation mark
      "\u203a", # Single right-pointing angle quotation mark
      "\u2041", # Caret insertion point
      "\u2044", # Fraction slash
      "\u2052", # Commercial minus sign
      "\u205f", # Medium mathematical space
      "\u2153", # Vulgar fraction one third
      "\u2154", # Vulgar fraction two thirds
      "\u2155", # Vulgar fraction one fifth
      "\u2156", # Vulgar fraction two fifths
      "\u2157", # Vulgar fraction three fifths
      "\u2158", # Vulgar fraction four fifths
      "\u2159", # Vulgar fraction one sixth
      "\u215a", # Vulgar fraction five sixths
      "\u215b", # Vulgar fraction one eight
      "\u215c", # Vulgar fraction three eighths
      "\u215d", # Vulgar fraction five eighths
      "\u215e", # Vulgar fraction seven eighths
      "\u215f", # Fraction numerator one
      "\u2215", # Division slash
      "\u2236", # Ratio
      "\u23ae", # Integral extension
      "\u2571", # Box drawings light diagonal upper right to lower left
      "\u29f6", # Solidus with overbar
      "\u29f8", # Big solidus
      "\u2afb", # Triple solidus binary relation
      "\u2afd", # Double solidus operator
      "\u2ff0", # Ideographic description character left to right
      "\u2ff1", # Ideographic description character above to below
      "\u2ff2", # Ideographic description character left to middle and right
      "\u2ff3", # Ideographic description character above to middle and below
      "\u2ff4", # Ideographic description character full surround
      "\u2ff5", # Ideographic description character surround from above
      "\u2ff6", # Ideographic description character surround from below
      "\u2ff7", # Ideographic description character surround from left
      "\u2ff8", # Ideographic description character surround from upper left
      "\u2ff9", # Ideographic description character surround from upper right
      "\u2ffa", # Ideographic description character surround from lower left
      "\u2ffb", # Ideographic description character overlaid
      "\u3000", # Ideographic space
      "\u3002", # Ideographic full stop
      "\u3014", # Left tortoise shell bracket
      "\u3015", # Right tortoise shell bracket
      "\u3033", # Vertical kana repeat mark upper half
      "\u30a0", # Katakana-hiragana double hyphen
      "\u3164", # Hangul filler
      "\u321d", # Parenthesized korean character ojeon
      "\u321e", # Parenthesized korean character o hu
      "\u33ae", # Square rad over s
      "\u33af", # Square rad over s squared
      "\u33c6", # Square c over kg
      "\u33df", # Square a over m
      "\ua789", # Modifier letter colon
      "\ufe14", # Presentation form for vertical semicolon
      "\ufe15", # Presentation form for vertical exclamation mark
      "\ufe3f", # Presentation form for vertical left angle bracket
      "\ufe5d", # Small left tortoise shell bracket
      "\ufe5e", # Small right tortoise shell bracket
      "\ufeff", # Zero-width no-break space
      "\uff0e", # Fullwidth full stop
      "\uff0f", # Fullwidth solidus
      "\uff61", # Halfwidth ideographic full stop
      "\uffa0", # Halfwidth hangul filler
      "\ufff9", # Interlinear annotation anchor
      "\ufffa", # Interlinear annotation separator
      "\ufffb", # Interlinear annotation terminator
      "\ufffc", # Object replacement character
      "\ufffd"  # Replacement character
    ]

    def allowed_chars_set
      @@allowed_chars_set ||= (read_allowed_idn_chars.chars.to_set - MOZILLA_DISALLOWED_CHARACTERS)
    end

    private
      # Built with bin/generate_allowed_idn_characters
      def read_allowed_idn_chars
        File.read("#{__dir__}/data/allowed_idn_characters.txt")
      end
  end

  def attack_detected?
    !label_set.subset?(self.class.allowed_chars_set)
  end
end
