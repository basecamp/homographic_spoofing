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

  test "sanitize uppercase and mixed-case confusable domain" do
    assert_sanitize "xn--pple-43d.com", "Аpple.com"
    assert_sanitize "APPLE.com", "APPLE.com"
  end

  # Ⱥ (U+023A) lowercases to ⱥ (U+2C65) under String#downcase but not under
  # regexp case folding, so recovering the original-cased label positionally —
  # rather than via /i — is what lets this uppercase spoof be sanitized.
  test "sanitize confusable domain with a special-cased character" do
    assert_sanitize "xn--pple-k49b.com", "Ⱥpple.com"
  end

  # İ (U+0130) lowercases to two codepoints (i + combining dot), so the label's
  # original casing is recovered by matching lowercase content rather than a
  # character offset, which the length change would otherwise shift.
  test "sanitize confusable domain with a length-changing lowercase" do
    assert_sanitize "xn--ipple-7fd.com", "İpple.com"
  end

  # PublicSuffix strips surrounding whitespace the raw domain still carries, so a
  # fixed offset into the domain would miss the label; content matching does not.
  test "sanitize confusable domain with surrounding whitespace" do
    assert_sanitize " xn--pple-43d.com ", " Аpple.com "
  end

  private
    def assert_sanitize(sanitized, domain)
      assert_equal sanitized, HomographicSpoofing::Sanitizer::Idn.sanitize(domain)
    end
end
