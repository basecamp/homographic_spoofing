class HomographicSpoofing::Detector::Rule::Idn::Context < HomographicSpoofing::Detector::Rule::Context
  attr_reader :tld, :tld_allowances

  # `tld_allowances` is shared by every label of one domain, so a decision that
  # depends only on the TLD is made once per domain rather than once per label.
  # Under a wildcard suffix such as "*.mm" the TLD carries a label the sender
  # chose, and scanning it again for every label would cost the label count
  # times its length.
  def initialize(label:, tld:, occurrence: 0, tld_allowances: {})
    @tld = tld
    @tld_allowances = tld_allowances
    super(label:, occurrence:)
  end
end
