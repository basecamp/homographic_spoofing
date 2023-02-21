require "test_helper"

class HomographicSpoofing::Sanitizer::IdnTest < ActiveSupport::TestCase
  test "sanitize" do
    assert_sanitize "င၀ဂခဂ.xn--titter-345b.net.mm", "င၀ဂခဂ.tᴡitter.net.mm"
    assert_sanitize "twitter.com", "twitter.com"
  end

  test "log violations" do
    logged_io = StringIO.new
    previous_logger, HomographicSpoofing::Sanitizer::Idn.logger = HomographicSpoofing::Sanitizer::Idn.logger, ActiveSupport::Logger.new(logged_io)

    assert_sanitize "xn--titter-345b.google.com", "tᴡitter.google.com"
    assert_match /EmailIDN Spoofing detected for: "[a-z_]+" on: "tᴡitter"/, logged_io.string
  ensure
    HomographicSpoofing::Sanitizer::Idn.logger = previous_logger
  end

  private
    def assert_sanitize(sanitized, domain)
      assert_equal sanitized, HomographicSpoofing::Sanitizer::Idn.sanitize(domain)
    end
end
