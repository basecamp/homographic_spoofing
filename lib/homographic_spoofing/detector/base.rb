class HomographicSpoofing::Detector::Base
  def self.detected?(label)
    new(label).detected?
  end

  def self.detections(label)
    new(label).detections
  end

  def initialize(label)
    @label = label
  end

  def detected?
    detections.any?
  end

  def detections
    rules.select(&:attack_detected?).map do |rule|
      HomographicSpoofing::Detector::Detection.new(rule.reason, rule.label)
    end
  rescue Encoding::CompatibilityError
    # String must be in Unicode.
    [ HomographicSpoofing::Detector::Detection.new("invalid_unicode", label) ]
  end

  private
    attr_reader :label

    def rules
      @rules ||= rule_classes.map { |klass| klass.new(context) }
    end

    def rule_classes
      raise NotImplementedError, "subclasses must override this"
    end

    def context
      @context ||= HomographicSpoofing::Detector::Rule::Context.new(label:)
    end
end
