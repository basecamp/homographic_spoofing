class HomographicSpoofing::Sanitizer::Base
  class_attribute :logger, default: HomographicSpoofing.logger

  def self.sanitize(field)
    new(field).sanitize
  end

  def initialize(field)
    @field = field
  end

  def sanitize
    detections = detector_class.new(field).detections
    detections.each { |detection| log(detection.reason, detection.label) }
    apply(field, detections)
  end

  private
    attr_reader :field

    # Punycode each offending label only within the component it came from. A
    # spanned detection carries the [offset, length] of its component, so a
    # domain-label spoof is confined to the domain and never rewrites a benign
    # local part that merely equals the same string — this is what keeps
    # "з@мир.з.example.com" punycoding the domain label "з" while leaving the "з"
    # mailbox intact. Spans are disjoint or nested (a display name read from a
    # comment the host's token carries), so they form a tree: each span's text is
    # rebuilt with its inner spans already rewritten, then rewritten itself, in
    # one pass over the field. A detection with no span (a bare IDN or quoted
    # string) spans the whole field and is applied last, over what remains.
    def apply(field, detections)
      return field.dup if detections.empty?

      whole, spanned = detections.partition { |detection| detection.span.nil? }
      edits = spanned.group_by(&:span).map do |(offset, length), group|
        Edit.new(offset, offset + length, group.map(&:label).uniq, [])
      end
      chars = field.chars
      replace_labels(splice(chars, 0, chars.length, nest(edits)), whole.map(&:label).uniq)
    end

    Edit = Struct.new(:start, :finish, :labels, :inner)

    # Arrange spans into a tree, outer before inner, in one pass over them sorted
    # by start. A span that overlaps an earlier sibling without nesting in it is
    # trimmed to start where that sibling ends.
    def nest(edits)
      outermost, open = [], []
      edits.sort_by { |edit| [ edit.start, -edit.finish ] }.each do |edit|
        open.pop while open.any? && open.last.finish < edit.finish
        siblings = open.empty? ? outermost : open.last.inner
        edit.start = [ edit.start, siblings.last.finish ].max if siblings.any?
        next if edit.start > edit.finish

        siblings << edit
        open << edit
      end
      outermost
    end

    def splice(chars, start, finish, edits)
      text, at = +"", start
      edits.each do |edit|
        text << chars[at...edit.start].join << replace_labels(splice(chars, edit.start, edit.finish, edit.inner), edit.labels)
        at = edit.finish
      end
      text << chars[at...finish].join
    end

    # Replace each label where it is a whole "."-delimited component of the
    # region, so an offending label is never rewritten as a substring of a benign
    # sibling (the Cyrillic digit-look-alike "з" that also sits inside
    # "магазин"), and every matching component is punycoded from its own
    # spelling — case-exact, so a spoof repeated in different casing is handled
    # per occurrence. A component is compared with its CFWS (comments and
    # surrounding whitespace, which the parser drops from the label it reports)
    # set aside, and only the label itself is rewritten, so "з(comment)" is
    # punycoded at the label and a comment beside it never sends the replacement
    # into a benign sibling. A label that is only a substring of a component (a
    # display name carrying spaces) has no whole component to match and falls
    # back to exact substring replacement.
    #
    # The region is scanned once for all labels, so sanitizing stays linear in
    # its length however many labels were detected.
    def replace_labels(region, labels)
      return region if labels.empty?

      components = label_components(region)
      present = components.to_set(&:bare)
      whole, partial = labels.partition { |label| present.include?(label) }
      whole = whole.to_set

      result = components.map { |component| whole.include?(component.bare) ? component.punycoded : component.text }.join
      partial.inject(result) { |text, label| text.gsub(label) { Dnsruby::Name.punycode(label) } }
    end

    # One "."-delimited component of a region: its text, the label it carries
    # with CFWS set aside (`bare`), and where that label starts in the text, past
    # any leading CFWS that may repeat it. Separators are components too, with no
    # label.
    Component = Struct.new(:text, :bare, :start) do
      def punycoded
        if text[start, bare.length] == bare
          text[0, start] + Dnsruby::Name.punycode(bare) + text[(start + bare.length)..]
        else
          text
        end
      end
    end

    # Split a region into label components on each "." outside comments and
    # quoted strings, in a single pass. Comments nest and honour backslash
    # escapes, as RFC 5322 has them, so a comment's own dots or parentheses
    # never split or end a label early.
    def label_components(region)
      components = []
      text, bare, start = +"", +"", nil
      depth, quoted, escaped = 0, false, false

      region.each_char do |char|
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
        elsif char == "("
          depth, commented = 1, true
        elsif char == '"'
          quoted = true
        elsif char == "."
          components << Component.new(text, bare.strip, start || 0) << Component.new(char, nil, 0)
          text, bare, start = +"", +"", nil
          next
        end

        unless commented
          start ||= text.length unless char.match?(/\s/)
          bare << char
        end
        text << char
      end

      components << Component.new(text, bare.strip, start || 0)
    end

    def detector_class
      raise NotImplementedError, "subclasses must override this"
    end

    def log(reason, label)
      self.class.logger.info("#{spoofing_type} Spoofing detected for: \"#{reason}\" on: \"#{label}\".") if self.class.logger
    end

    def spoofing_type
      raise NotImplementedError, "subclasses must override this"
    end
end
