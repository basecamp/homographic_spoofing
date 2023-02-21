# Detects spoofing homographic attacks for the Quoted-String-Part of an email address.
#
# The implementation strictly follows Unicode guidelines for Email Security Profiles for Identifiers.
#
# See http://www.unicode.org/reports/tr39/#Email_Security_Profiles.
class HomographicSpoofing::Detector::QuotedString < HomographicSpoofing::Detector::Base
  private
    def rule_classes
      [ HomographicSpoofing::Detector::Rule::QuotedString::Nfc,
        HomographicSpoofing::Detector::Rule::QuotedString::BidiControl,
        HomographicSpoofing::Detector::Rule::QuotedString::NonspacingMarks ]
    end
end
