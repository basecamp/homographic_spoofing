# 8. of Google Chrome IDN policy
#
# Allow middle dot (U+00B7) only on Catalan domains when between two 'l's, to
# permit the Catalan character ela geminada to be expressed.
# See https://tools.ietf.org/html/rfc5892#appendix-A.3 for details.
class HomographicSpoofing::Detector::Rule::Idn::UnsafeMiddleDot < HomographicSpoofing::Detector::Rule::Idn::Base
  def attack_detected?
    label.scan(/l?·l?/).find do |match|
      tld != "cat" || match != "l·l"
    end
  end
end
