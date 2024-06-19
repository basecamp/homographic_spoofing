# HomographicSpoofing

Toolkit to both detect and sanitize [homographic spoofing attacks](https://en.wikipedia.org/wiki/IDN_homograph_attack) in URLs and Email addresses.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "homographic_spoofing"
```

And then execute:

```bash
$ bundle
```

Or install it yourself as:

```bash
$ gem install homographic_spoofing
```
## Configuration

If `HomographicSpoofing.logger` is set to a Logger instance, the gem will log all the violations found. If you're using Rails,
it is automatically configured to use `Rails.logger`, otheriwse you can set it manually:

```ruby
HomographicSpoofing.logger = Logger.new("log/homographic_spoofing.log")
```

## Usage

### IDN

[What is an IDN](https://en.wikipedia.org/wiki/Internationalized_domain_name)

**Check if an IDN is an homographic spoof**

```ruby
HomographicSpoofing.idn_spoof?("www.basecаmp.com")
# => true, uses cyrillic 'а' instead of latin 'a'
HomographicSpoofing.idn_spoof?("www.basecamp.com")
# => false
```

**Sanitize an IDN**

The library can also sanitize an IDN by converting all confusable characters to their punycode representation.

```ruby
HomographicSpoofing.sanitize_idn("www.basecаmp.com")
# => "www.xn--basecmp-6fg.com"
HomographicSpoofing.sanitize_idn("www.basecamp.com")
# => "www.basecamp.com"
```

### Email addresses

An email address is formed from three main parts:

"Jacopo Beschi" <<jacopo.beschi@basecamp.com>>

- The domain-part is "basecamp.com"
- The local-part is "jacopo.beschi"
- The quoted-string-part is "Jacopo Beschi"

**Check if an email_address is an homographic spoof**

```ruby
HomographicSpoofing.email_address_spoof?(%{"Jacopo Beschi" <jacopo.beschi@basecаmp.com>})
# => true, uses cyrillic 'а' instead of latin 'a'
```

**Sanitize an email_address**

```ruby
>> HomographicSpoofing.sanitize_email_address(%{"Jacopo Beschi" <jacopo.beschi@basecаmp.com>})
# => "\"Jacopo Beschi\" <jacopo.beschi@xn--basecmp-6fg.com>"
```

**Check if an email_address local-part is an homographic spoof**

```ruby
HomographicSpoofing.email_local_spoof?("jacopo.beschi")
# => false
```

**Check if an email_address quoted-string-part is an homographic spoof**

```ruby
HomographicSpoofing.email_name_spoof?("Jacopo Beschi")
# => false
```

**Sanitize an email_address quoted-string-part**

```ruby
HomographicSpoofing.sanitize_email_name("Jacopo Beschi")
# => "Jacopo Beschi"
```

## Requirements

Ruby >= 3.1.0

## Development

To experiment, start the console with `bin/console`.
Run the test via `bin/test`.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/basecamp/homographic_spoofing.

## License

The IDN spoof detection algorithms are inspired by Chromium's [spoof_check](https://source.chromium.org/chromium/chromium/src/+/main:components/url_formatter/spoof_checks/) source code.

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
