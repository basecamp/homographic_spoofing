# See http://www.unicode.org/reports/tr39/#Email_Security_Profiles nonspacing marks.
class HomographicSpoofing::Detector::Rule::QuotedString::NonspacingMarks < HomographicSpoofing::Detector::Rule::Base
  def attack_detected?
    nonspacing_marks_regexp.match?(label)
  end

  private
    def nonspacing_marks_regexp
      # 5 or more nonspacing marks in a row or 2 or more repetitions of the same nonspacing mark.
      @@nonspacing_marks_regexp ||= /[#{nonspacing_marks}]{5,}|([#{nonspacing_marks}])\1/
    end

    def nonspacing_marks
      @nonspacing_marks ||= read_nonspacing_marks
    end

    # Built with script/development/generate_nonspacing_marks.rb
    def read_nonspacing_marks
      File.read("#{__dir__}/data/nonspacing_marks.txt")
    end
end
