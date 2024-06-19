class HomographicSpoofing::Railtie < ::Rails::Railtie
  initializer "homographic_spoofing.logger" do
    HomographicSpoofing.logger ||= Rails.logger
  end
end
