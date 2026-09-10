require "test_helper"

class HomographicSpoofing::Sanitizer::EmailAddressTest < ActiveSupport::TestCase
  test "sanitize name" do
    assert_sanitize "Jacopo Beschi <jacopo@37signals.com>", "Jacopo Beschi <jacopo@37signals.com>"
    assert_sanitize "xn--jacopo beschi-ny6g <jacopo@37signals.com>", "Jacopo Beschi\u202e <jacopo@37signals.com>"
    assert_sanitize "xn--jacopo beschi-ny6g (My email address) <jacopo@37signals.com>", "Jacopo Beschi\u202e (My email address) <jacopo@37signals.com>"
  end

  test "sanitize local part" do
    assert_sanitize "xn--titter-345b@xn--titter-345b.com", "tᴡitter@tᴡitter.com"
    assert_sanitize "xn--titter-345b@twitter.com", "tᴡitter@twitter.com"
    assert_sanitize "jacopo@twitter.com", "jacopo@twitter.com"
    assert_sanitize "Twitter <xn--titter-345b@twitter.com>", "Twitter <tᴡitter@twitter.com>"
  end

  test "sanitize idn" do
    assert_sanitize "jacopo@xn--titter-345b.com", "jacopo@tᴡitter.com"
    assert_sanitize "jacopo@xn--titter-345b.င၀ဂခဂ.net.mm", "jacopo@tᴡitter.င၀ဂခဂ.net.mm"
    assert_sanitize "jacopo@င၀ဂခဂ.xn--titter-345b.net.mm", "jacopo@င၀ဂခဂ.tᴡitter.net.mm"
    assert_sanitize "jacopo@xn--titter-345b.xn--gogle-lkg.com", "jacopo@tᴡitter.gօogle.com"
    assert_sanitize "jacopo@twitter.com", "jacopo@twitter.com"
  end

  test "sanitize invalid email address" do
    assert_sanitize "@tᴡitter", "@tᴡitter"
  end

  test "log violations" do
    logged_io = StringIO.new
    previous_logger, HomographicSpoofing::Sanitizer::EmailAddress.logger = HomographicSpoofing::Sanitizer::EmailAddress.logger, ActiveSupport::Logger.new(logged_io)

    assert_sanitize "xn--titter-345b@xn--titter-345b.xn--gogle-lkg.com", "tᴡitter@tᴡitter.gօogle.com"
    assert_match /EmailAddress Spoofing detected for: "dot_atom_text" on: "tᴡitter"/, logged_io.string
    assert_match /EmailAddress Spoofing detected for: "[a-z_]+" on: "tᴡitter"/, logged_io.string
    assert_match /EmailAddress Spoofing detected for: "[a-z_]+" on: "gօogle"/, logged_io.string
  ensure
    HomographicSpoofing::Sanitizer::EmailAddress.logger = previous_logger
  end

  test "sanitize uppercase confusable idn domain" do
    assert_sanitize "jacopo@xn--pple-43d.com", "jacopo@Аpple.com"
  end

  test "sanitize uppercase confusable idn domain leaves benign ascii name untouched" do
    assert_sanitize "Apple Support <x@xn--pple-43d.com>", "Apple Support <x@аpple.com>"
  end

  # The name is only substituted when its own detector flags it. A confusable
  # local part must not bleed into a name that differs from it by case: the long
  # s (ſ) case-folds to ASCII s, and the small capital w (ᴡ) shares a case pair
  # with ASCII W, but each name here is left to its quoted-string detector.
  test "confusable local part does not mutate a case-variant name" do
    assert_sanitize "Support <support@example.com>", "Support <ſupport@example.com>"
    assert_sanitize "Tᴡitter <xn--titter-345b@twitter.com>", "Tᴡitter <tᴡitter@twitter.com>"
  end

  # Per-label domain detection punycodes the offending label as a whole
  # component: a benign domain label that merely contains the same character
  # (магазин contains the digit-look-alike "з") stays intact, and a spoofed
  # label repeated in different casing is sanitized at every position.
  test "sanitize a domain label that is a substring of a benign sibling label" do
    assert_sanitize "jacopo@магазин.xn--g1a.example.com", "jacopo@магазин.з.example.com"
  end

  test "sanitize a confusable domain label repeated with different casing" do
    assert_sanitize "jacopo@xn--pple-43d.xn--pple-43d.example.com", "jacopo@Аpple.аpple.example.com"
  end

  # A benign local part that differs only by case from an offending domain label
  # must not be punycoded: local parts can be case-sensitive, so rewriting the
  # mailbox would change the recipient. Matching whole components case-exactly
  # keeps the domain detection from bleeding across the "@".
  test "confusable domain label does not mutate a case-variant local part" do
    assert_sanitize "РАУ@xn--80a5ak.com", "РАУ@рау.com"
  end

  private
    def assert_sanitize(sanitized, email_address)
      assert_equal sanitized, HomographicSpoofing::Sanitizer::EmailAddress.sanitize(email_address)
    end
end
