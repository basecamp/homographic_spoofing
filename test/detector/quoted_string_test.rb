require "test_helper"

class HomographicSpoofing::Detector::QuotedStringTest < ActiveSupport::TestCase
  test "Unicode NFC format" do
    # Invalid unicode
    assert_attack("text".force_encoding("ISO-8859-1"), reason: "invalid_unicode")
    assert_attack("1A\u030A3rf", reason: "nfc")
    assert_safe("scope")
  end

  test "bidicontrol" do
    # Right-to-left override bidicontrol character
    assert_attack("1\u202e3rf", reason: "bidi_control")
  end

  test "nonspacing marks" do
    # More than four nonspacing marks in a row
    assert_attack("1\u0300\u0301\u0302\u0303\u030423", reason: "nonspacing_marks")
    # Two repetitions
    assert_attack("1\u0300\u030023", reason: "nonspacing_marks")
    # Three repetitions
    assert_attack("1\u0300\u0300\u030023", reason: "nonspacing_marks")
    assert_safe("12\u03003\u0300rf")
    assert_safe("1123rf")
  end

  private
    def assert_attack(label, reason: nil)
      assert HomographicSpoofing::Detector::QuotedString.detected?(label), "No Attack detected for #{label}."
      if reason
        detections = HomographicSpoofing::Detector::QuotedString.detections(label)
        assert_includes detections.map(&:reason), reason
      end
    end

    def assert_safe(label)
      assert_not HomographicSpoofing::Detector::QuotedString.detected?(label), "Attack detected for #{label}."
    end
end
