class HomographicSpoofing::Detector::Rule::Base
  delegate :scripts, :label, :label_set, :occurrence, to: :@context

  def initialize(context)
    @context = context
  end

  def attack_detected?
    raise NotImplementedError, "subclasses must override this"
  end

  def reason
    self.class.name.demodulize.underscore
  end
end
