# Detects spoofing homographic attacks for the Local-Part of an email address.
#
# The implementation strictly follows Unicode guidelines for Email Security Profiles for Identifiers.
#
# See http://www.unicode.org/reports/tr39/#Email_Security_Profiles.
class HomographicSpoofing::Detector::Local < HomographicSpoofing::Detector::Base
  private
    def rule_classes
      [ HomographicSpoofing::Detector::Rule::Local::Nfkc,
        HomographicSpoofing::Detector::Rule::MixedScripts,
        HomographicSpoofing::Detector::Rule::MixedDigits,
        HomographicSpoofing::Detector::Rule::Local::DotAtomText ]
    end
end
