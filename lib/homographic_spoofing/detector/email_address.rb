class HomographicSpoofing::Detector::EmailAddress
  def self.detected?(email_address)
    new(email_address).detected?
  end

  def self.detections(email_address)
    new(email_address).detections
  end

  def initialize(email_address)
    @email_address = email_address
  end

  def detected?
    detections.any?
  end

  def detections
    mail_address = mail_address_wrap(email_address)
    spans = component_spans(mail_address)
    [].tap do |result|
      result.concat detections_for(text: mail_address.name,   type: "quoted_string", span: spans[:name])
      result.concat detections_for(text: mail_address.local,  type: "local",         span: spans[:local])
      result.concat detections_for(text: mail_address.domain, type: "idn",           span: spans[:domain])
    end
  rescue Mail::Field::FieldError
    # Do not analyse invalid email addresses.
    []
  end

  private
    attr_reader :email_address

    # Tag each detection with the [offset, length] of the component it came from
    # so the sanitizer scopes the punycode replacement to that component alone —
    # a domain-label spoof never rewrites a benign local part that merely equals
    # the same string.
    def detections_for(text:, type:, span:)
      if text
        detector_for(type:, text:).detections.each { |detection| detection.span = span }
      else
        []
      end
    end

    def detector_for(type:, text:)
      "HomographicSpoofing::Detector::#{type.camelize}".constantize.new(text)
    end

    # Derive each component's [offset, length] span from parser token boundaries,
    # not by searching the raw field for the stripped parts. The addr-spec built
    # from the parser's *raw* local and domain — which keep the CFWS the stripped
    # forms drop — is by construction a contiguous substring of the field, so its
    # offset pins the mailbox and host spans exactly even when a comment or stray
    # whitespace sits inside the address. The offset is taken inside the structural
    # angle-address when there is one, so a display name or comment that repeats
    # the addr-spec cannot divert the recipient's replacement onto itself. Only the
    # display name — never the recipient — is still located by text (outside any
    # comment), since a mislocated name only misplaces a cosmetic fix. When the
    # field is not a raw string (a Mail::Address handed straight to a detection
    # query) there is nothing to sanitize, so spans are left nil.
    def component_spans(mail_address)
      local, domain, name = mail_address.local, mail_address.domain, mail_address.name
      return {} unless email_address.is_a?(String)

      raw_local, raw_domain = raw_addr_spec_parts
      addr = "#{raw_local}@#{raw_domain}" if raw_local && raw_domain
      at = addr_offset(addr) if addr

      if at
        { name:   (locate(name, avoid: [ at, addr.length ]) if name),
          local:  ([ at, raw_local.length ] if local),
          domain: ([ at + raw_local.length + 1, raw_domain.length ] if domain) }
      else
        structural_spans(local, domain, name)
      end
    end

    # The raw local and domain of the addr-spec as they appear in the field, CFWS
    # included, from the address parser — or nils when it cannot supply them.
    def raw_addr_spec_parts
      parsed = Mail::Parsers::AddressListsParser.parse(email_address).addresses.first
      [ parsed&.local, parsed&.domain ]
    rescue StandardError
      [ nil, nil ]
    end

    # The addr-spec's offset in the field. When the field has a structural
    # angle-address — its "<" outside every quoted string and comment, since a
    # quoted display name or a comment may itself spell out "<local@domain>" — the
    # addr-spec is searched for inside it rather than matched as "<addr>", because
    # an obsolete route ("<@relay:local@domain>") may precede it; a copy of the
    # addr-spec anywhere else in the field is never the recipient. Without an
    # angle-address, the first bare occurrence outside any comment.
    def addr_offset(addr)
      lt, gt = angle_address
      if lt
        at = structural_index(addr, from: lt + 1)
        at if at && at + addr.length <= gt
      else
        structural_index(addr)
      end
    end

    # The offsets of the "<" and ">" of the structural angle-address, or nil when
    # the field has none.
    def angle_address
      lt = structural_index("<")
      gt = structural_index(">", from: lt) if lt
      [ lt, gt ] if lt && gt
    end

    # The first occurrence of `needle` at or after `from` that starts outside
    # every quoted string, domain literal and comment in the field.
    def structural_index(needle, from: 0)
      enclosed, commented = enclosures
      while (at = email_address.index(needle, from))
        return at unless enclosed[at] || commented[at]
        from = at + 1
      end
      nil
    end

    # Which character offsets of the field sit inside a quoted string or a domain
    # literal, and which inside a (nestable) comment. Each opening delimiter is
    # outside its own enclosure, so a needle may begin with one ('"john"@host');
    # the closing delimiter is inside. Backslash escapes are honored in all
    # three, and inside a comment neither quotes nor literals have structure —
    # only nesting parentheses do.
    def enclosures
      @enclosures ||= begin
        enclosed, commented = Array.new(email_address.length, false), Array.new(email_address.length, false)
        closer, depth, escaped = nil, 0, false
        email_address.each_char.with_index do |char, i|
          enclosed[i], commented[i] = !closer.nil?, depth > 0
          if escaped
            escaped = false
          elsif char == "\\" && (closer || depth > 0)
            escaped = true
          elsif closer
            closer = nil if char == closer
          elsif depth > 0
            depth += 1 if char == "("
            depth -= 1 if char == ")"
          elsif char == '"'
            closer = '"'
          elsif char == "["
            closer = "]"
          elsif char == "("
            depth = 1
          end
        end
        [ enclosed, commented ]
      end
    end

    # Fallback when the parser yields no raw addr-spec: bound the components by the
    # structural delimiters instead. The addr-spec sits between the angle brackets
    # when present (split at its "@"), otherwise leads the field at the first "@".
    def structural_spans(local, domain, name)
      lt, gt = angle_address
      at = structural_index("@", from: lt || 0)

      if lt && at && at < gt
        { name:   (locate(name, avoid: [ lt, gt - lt + 1 ]) if name),
          local:  ([ lt + 1, at - lt - 1 ] if local),
          domain: ([ at + 1, gt - at - 1 ] if domain) }
      elsif at
        { name:   (locate(name) if name),
          local:  ([ 0, at ] if local),
          domain: (locate(domain, from: at + 1) if domain) }
      else
        {}
      end
    end

    # The first occurrence of `text` in the field at or after `from` outside
    # `avoid` (the angle-address, when locating a display name that shares a
    # spelling with the mailbox or host), preferring one outside any comment —
    # leading CFWS may repeat a display name — but accepting one inside a comment
    # when that is the only place it occurs, since the parser takes a display
    # name from a trailing comment ("user@host (Name)").
    def locate(text, from: 0, avoid: nil)
      locate_outside(text, from:, avoid:, commented: enclosures.last) || locate_outside(text, from:, avoid:)
    end

    def locate_outside(text, from:, avoid:, commented: [])
      while (at = email_address.index(text, from))
        span = [ at, text.length ]
        avoided = avoid && at >= avoid[0] && at < avoid[0] + avoid[1]
        return span unless avoided || commented[at]
        from = at + 1
      end
      nil
    end

    def mail_address_wrap(email_address)
      email_address.is_a?(Mail::Address) ? email_address : Mail::Address.new(email_address)
    end
end
