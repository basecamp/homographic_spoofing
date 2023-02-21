class HomographicSpoofing::Detector::Rule::Idn::ScriptSpecific < HomographicSpoofing::Detector::Rule::Idn::Base
  def attack_detected?
    latin_spoof? || icelandic_spoof? || azerbaijan_spoof?
  end

  private
    LATN = "Latin"
    # Disallow non-ASCII Latin letters to mix with a non-Latin script.
    # Note that the non-ASCII Latin check should not be applied when the entire label is made of Latin.
    def latin_spoof?
      scripts != Set[LATN] && non_ascii_latin_letters.present?
    end

    def non_ascii_latin_letters
      label.scan(/\p{latin}/).reject { _1 =~ /[a-z0-9]/ }
    end

    ICELANDIC_CHARACTERS = %w[ þ ð ].to_set
    # Latin small letter thorn ("þ", U+00FE) can be used to spoof both b and p.
    # It's used in modern Icelandic orthography, so allow it for the Icelandic
    # ccTLD (.is) but block in any other TLD. Also block Latin small letter eth
    # ("ð", U+00F0) which can be used to spoof the letter o.
    def icelandic_spoof?
      tld != "is" && (label_set & ICELANDIC_CHARACTERS).any?
    end

    # ə is only allowed under the .az TLD.
    def azerbaijan_spoof?
      tld != "az" && label_set.include?("ə")
    end
end
