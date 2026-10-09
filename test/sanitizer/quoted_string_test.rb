require "test_helper"

class HomographicSpoofing::Sanitizer::QuotedStringTest < ActiveSupport::TestCase
  test "sanitize" do
    assert_equal "xn--13rf-vd7a", HomographicSpoofing::Sanitizer::QuotedString.sanitize("1\u202e3rf")
  end

  test "sanitize a name that isn't UTF-8" do
    assert_equal "xn--13rf-vd7a".encode("UTF-16LE"), HomographicSpoofing.sanitize_email_name("1\u202e3rf".encode("UTF-16LE"))
  end
end
