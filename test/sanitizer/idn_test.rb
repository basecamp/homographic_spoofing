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

  # Per-label detection means the offending label is punycoded as a whole
  # component, not as a substring: a benign sibling that merely contains the
  # same character (магазин contains the digit-look-alike Cyrillic "з") must be
  # left intact.
  test "sanitize an offending label that is a substring of a benign sibling label" do
    assert_sanitize "магазин.xn--g1a.example.com", "магазин.з.example.com"
  end

  # A spoofed label repeated in different casing must be sanitized at every
  # position, each occurrence punycoded from its own spelling.
  test "sanitize a confusable label repeated with different casing across labels" do
    assert_sanitize "xn--pple-43d.xn--pple-43d.example.com", "Аpple.аpple.example.com"
  end

  # The offending label's original casing must be recovered at a label boundary,
  # not from its appearance inside a longer sibling. The standalone "з" is the
  # attack; the "З" inside "магаЗин" is incidental and must be left intact.
  test "sanitize an offending label whose lowercase appears inside a sibling label" do
    assert_sanitize "магаЗин.xn--g1a.example.com", "магаЗин.з.example.com"
  end

  # The email-address path scopes each replacement to the component it came
  # from; the bare-IDN path has a single component — the whole domain — so
  # part-scoping is a no-op here and this stays identical: the offending label
  # "з" is punycoded, its benign sibling "мир" untouched.
  test "part-scoping does not change bare-IDN sanitizing" do
    assert_sanitize "мир.xn--g1a.example.com", "мир.з.example.com"
  end

  private
    def assert_sanitize(sanitized, domain)
      assert_equal sanitized, HomographicSpoofing::Sanitizer::Idn.sanitize(domain)
    end
end
