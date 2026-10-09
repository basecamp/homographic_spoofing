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
      result.concat detections_for(text: mailbox(mail_address), type: "local",         span: spans[:local])
      result.concat detections_for(text: mail_address.domain, type: "idn",           span: spans[:domain])
      route_domains.each { |domain, span| result.concat detections_for(text: domain, type: "idn", span:) }
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
        { name:   (name_span(name, avoid: [ at, addr.length ]) if name),
          local:  (local_span(at, raw_local) if local),
          domain: ([ at + raw_local.length + 1, raw_domain.length ] if domain) }
      else
        structural_spans(local, domain, name)
      end
    end

    # The raw local and domain of the addr-spec as they appear in the field, CFWS
    # included, from the address parser — or nils when it cannot supply them.
    def raw_addr_spec_parts
      [ parsed_address&.local, parsed_address&.domain ]
    end

    def parsed_address
      return @parsed_address if defined?(@parsed_address)
      @parsed_address = Mail::Parsers::AddressListsParser.parse(email_address).addresses.first
    rescue StandardError
      @parsed_address = nil
    end

    # The mailbox. Mail::Address#local keeps an obsolete route ("@relay:" in
    # "<@relay:local@domain>") in front of it; the route is a list of domains,
    # not part of the mailbox, so it is set aside here and its domains are
    # checked as domains (see #route_domains). Each part is then punycoded on its
    # own, and the route's "@", "," and ":" stay as they are.
    #
    # Comments are set aside too: they are not part of the mailbox, and the
    # parser may take the display name from one ("<local(Name)@host>"), so the
    # name's replacement must not change the text the mailbox is matched by.
    def mailbox(mail_address)
      local, route = mail_address.local, parsed_address&.obs_domain_list
      local = local.delete_prefix(route) if route.present? && local
      without_comments(local)&.strip
    end

    # The text with its comments removed, honouring nesting, quoted strings and
    # backslash escapes, in one pass.
    def without_comments(text)
      return text unless text&.include?("(")

      bare, depth, quoted, escaped = +"", 0, false, false
      text.each_char do |char|
        commented = depth > 0
        if escaped
          escaped = false
        elsif char == "\\" && (commented || quoted)
          escaped = true
        elsif commented
          depth += 1 if char == "("
          depth -= 1 if char == ")"
        elsif quoted
          quoted = false if char == '"'
        elsif char == '"'
          quoted = true
        elsif char == "("
          depth, commented = 1, true
        end
        bare << char unless commented
      end
      bare
    end

    # Each domain of an obsolete route, with its span in the field: the route
    # sits inside the structural angle-address, before the addr-spec.
    def route_domains
      route = parsed_address&.obs_domain_list
      return [] unless email_address.is_a?(String) && route.present?

      lt, gt = angle_address
      start = structural_index(route, from: lt + 1) if lt
      return [] unless start && start + route.length <= gt

      route_entries(route).filter_map do |domain, offset, length|
        [ domain, [ start + offset, length ] ] if domain.present?
      end
    end

    # Split a route ("@a.example, @b.example:") into its domains in one pass, on
    # each "," or ":" outside comments. Each entry's span starts after its "@";
    # its domain is checked with comments and whitespace set aside (the obsolete
    # syntax allows both between labels), while the sanitizer, which also sets
    # them aside per label, rewrites only the labels within the span.
    def route_entries(route)
      entries = []
      bare, at, entry_start, depth, escaped = +"", nil, 0, 0, false

      route.each_char.with_index do |char, index|
        commented = depth > 0
        if escaped
          escaped = false
        elsif commented && char == "\\"
          escaped = true
        elsif commented
          depth += 1 if char == "("
          depth -= 1 if char == ")"
        elsif char == "("
          depth, commented = 1, true
        elsif char == "," || char == ":"
          entries << [ bare.gsub(/\s/, ""), at || entry_start, index - (at || entry_start) ]
          bare, at, entry_start = +"", nil, index + 1
          next
        elsif char == "@" && at.nil?
          at = index + 1
          next
        end
        bare << char unless commented || at.nil?
      end

      entries << [ bare.gsub(/\s/, ""), at || entry_start, route.length - (at || entry_start) ]
    end

    def local_span(at, raw_local)
      [ at, raw_local.length ]
    end

    # The display name's span. When the name the parser reports is not in the
    # field as written (it unescapes quoted pairs, so "\\x" reads as "x"), there
    # is no text to rewrite safely: its span is empty, so the detection is still
    # reported but the field is left as is rather than rewritten across an
    # escape or onto the mailbox or host.
    def name_span(name, avoid: nil)
      locate(name, avoid:) || [ 0, 0 ]
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
      enclosed, commented, _quoted_pair = enclosures
      while (at = index_in_field(needle, from))
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
        length = email_address.length
        enclosed, commented, quoted_pair = Array.new(length, false), Array.new(length, false), Array.new(length, false)
        closer, depth, escaped = nil, 0, false
        email_address.each_char.with_index do |char, i|
          enclosed[i], commented[i] = !closer.nil?, depth > 0
          if escaped
            escaped = false
            quoted_pair[i] = true
          elsif char == "\\" && (closer || depth > 0)
            escaped = true
            quoted_pair[i] = true
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
        [ enclosed, commented, quoted_pair ]
      end
    end

    # Fallback when the parser yields no raw addr-spec: bound the components by the
    # structural delimiters instead. The addr-spec sits between the angle brackets
    # when present (split at its "@"), otherwise leads the field at the first "@".
    def structural_spans(local, domain, name)
      lt, gt = angle_address
      at = lt ? last_structural_at(lt, gt) : structural_index("@")

      if lt && at && at < gt
        { name:   (name_span(name, avoid: [ lt, gt - lt + 1 ]) if name),
          local:  ([ lt + 1, at - lt - 1 ] if local),
          domain: ([ at + 1, gt - at - 1 ] if domain) }
      elsif at
        { name:   (name_span(name) if name),
          local:  ([ 0, at ] if local),
          domain: (locate(domain, from: at + 1) if domain) }
      else
        {}
      end
    end

    # The addr-spec's "@" inside the angle-address: the last structural one, since
    # an obsolete route ("<@relay:local@domain>") puts its own before it.
    def last_structural_at(lt, gt)
      last = nil
      while (at = structural_index("@", from: (last || lt) + 1)) && at < gt
        last = at
      end
      last
    end

    # The first occurrence of `text` in the field at or after `from` that lies
    # wholly outside every comment and outside `avoid` (the addr-spec, when
    # locating a display name that shares a spelling with the mailbox or host);
    # leading CFWS may repeat a display name. Failing that, the first occurrence
    # wholly inside one comment: the parser takes a display name from a trailing
    # comment ("user@host (Name)"), which its raw domain token also carries, and
    # a comment is never the mailbox or host even when it sits inside `avoid`.
    # An occurrence that crosses a comment's edge is neither, so it never sends
    # a display name's replacement into the mailbox.
    def locate(text, from: 0, avoid: nil)
      outside = comment_runs(commented: false).flat_map { |range| outside_of(range, avoid) }
      search_ranges(text, outside, from:) || search_ranges(text, comment_runs(commented: true), from:)
    end

    # The maximal [start, finish) runs of characters inside (or outside)
    # comments, without the parentheses that open and close each comment and
    # without quoted pairs ("\\(" and the like), so a display name's replacement
    # can never move a comment's edge or separate an escape from what it escapes.
    # The parser unescapes quoted pairs in the name it reports, so a name that
    # carries one is not in the field as written anyway.
    def comment_runs(commented:)
      @comment_runs ||= begin
        char_to_byte, _byte_to_char = offset_tables
        delimiter = ->(index) { field_bytes.getbyte(char_to_byte[index]) }
        _enclosed, inside_comment, quoted_pair = enclosures
        keys = inside_comment.each_with_index.map { |inside, index| quoted_pair[index] ? :quoted_pair : inside }
        keys.each_with_index.chunk_while { |(a, _), (b, _)| a == b }.filter_map do |run|
          inside, start, finish = run.first.first, run.first.last, run.last.last + 1
          next if inside == :quoted_pair

          finish -= 1 if inside && delimiter.(finish - 1) == ")".ord
          finish -= 1 if !inside && finish < char_to_byte.length - 1 && delimiter.(finish - 1) == "(".ord
          [ inside, start, finish ]
        end
      end
      @comment_runs.filter_map { |inside, start, finish| [ start, finish ] if inside == commented && start < finish }
    end

    def outside_of((start, finish), avoid)
      return [ [ start, finish ] ] unless avoid

      [ [ start, [ finish, avoid[0] ].min ], [ [ start, avoid[0] + avoid[1] ].max, finish ] ].reject { |a, b| a >= b }
    end

    # The first occurrence of `text` wholly inside one of `ranges`, searching
    # each range once, so the cost stays linear however often `text` overlaps
    # itself.
    def search_ranges(text, ranges, from:)
      char_to_byte, byte_to_char = offset_tables
      needle, length = text.b, text.length
      ranges.each do |start, finish|
        start = [ start, from ].max
        next if finish - start < length

        at = field_bytes.byteslice(char_to_byte[start]...char_to_byte[finish]).index(needle)
        return [ byte_to_char[char_to_byte[start] + at], length ] if at
      end
      nil
    end

    # The first occurrence of `needle` at or after character offset `from`.
    # String#index converts a character offset by walking a multibyte string
    # from its start on every call, so a loop of searches over a long field turns
    # quadratic. Search the field's bytes instead, where an offset costs nothing
    # and a UTF-8 match always starts on a character boundary, and map between
    # bytes and characters through tables built once.
    def index_in_field(needle, from)
      char_to_byte, byte_to_char = offset_tables
      return nil if from >= char_to_byte.length

      at = field_bytes.index(needle.b, char_to_byte[from])
      byte_to_char[at] if at
    end

    def field_bytes
      @field_bytes ||= email_address.b
    end

    def offset_tables
      @offset_tables ||= begin
        char_to_byte, byte_to_char = [], []
        email_address.each_char.with_index do |char, index|
          char_to_byte << byte_to_char.length
          char.bytesize.times { byte_to_char << index }
        end
        char_to_byte << byte_to_char.length
        byte_to_char << email_address.length
        [ char_to_byte, byte_to_char ]
      end
    end


    def mail_address_wrap(email_address)
      email_address.is_a?(Mail::Address) ? email_address : Mail::Address.new(email_address)
    end
end
