require "test_helper"

class HomographicSpoofing::Detector::EmailAddressTest < ActiveSupport::TestCase
  test "detect name" do
    assert_attack "Jacopo Beschi\u202e <jacopo@37signals.com>"
    assert_safe "Jacopo Beschi <jacopo@37signals.com>"
  end

  test "detect local part" do
    assert_attack "tᴡitter@twitter.com"
  end

  test "detect idn" do
    assert_attack "jacopo@tᴡitter.com"
  end

  test "ignore nil email address parts" do
    # nil name
    assert_safe "jacopo@37signals.com"
    # nil local
    assert_safe "\"jacopo beschi\" <jacopobeschi>"
    # nil domain
    assert_safe "jacopo"
  end

  private
    def assert_attack(email_address)
      assert HomographicSpoofing::Detector::EmailAddress.detected?(email_address), "No attack detected for #{email_address}."
    end

    def assert_safe(email_address)
      assert_not HomographicSpoofing::Detector::EmailAddress.detected?(email_address), "Attack detected for #{email_address}."
    end
end
