require "test_helper"

class HomographicSpoofing::Sanitizer::QuotedStringTest < ActiveSupport::TestCase
  test "sanitize" do
    assert_equal "xn--13rf-vd7a", HomographicSpoofing::Sanitizer::QuotedString.sanitize("1\u202e3rf")
  end
end
