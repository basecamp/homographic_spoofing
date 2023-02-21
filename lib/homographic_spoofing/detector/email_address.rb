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
    [].tap do |result|
      result.concat detector_for(part: mail_address.name,   type: "quoted_string").detections if mail_address.name
      result.concat detector_for(part: mail_address.local,  type: "local").detections if mail_address.local
      result.concat detector_for(part: mail_address.domain, type: "idn").detections if mail_address.domain
    end
  rescue Mail::Field::FieldError
    # Do not analyse invalid email addresses.
    []
  end

  private
    attr_reader :email_address

    def detector_for(type:, part:)
      "HomographicSpoofing::Detector::#{type.camelize}".constantize.new(part)
    end

    def mail_address_wrap(email_address)
      email_address.is_a?(Mail::Address) ? email_address : Mail::Address.new(email_address)
    end
end
