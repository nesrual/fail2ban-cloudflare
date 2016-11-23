require 'net/https'
require 'uri'
require 'json'
require 'ipaddr'

# Various settings
API_ENDPOINT = 'https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules'.freeze
CLOUDFLARE_USERNAME     = 'YOUR_CLOUDFLARE_USERNAME_GOES_HERE'.freeze
CLOUDFLARE_API_KEY      = 'YOUR_API_KEY_GOES_HERE'.freeze

# Timeout settings
HTTP_READ_TIMEOUT = 10

# Optional proxy settings
HTTP_PROXY_SERVER   = nil
HTTP_PROXY_PORT     = nil
HTTP_PROXY_USERNAME = nil
HTTP_PROXY_PASSWORD = nil

# Our arguments provides from the command line
command = ARGV[0]

begin
  ip = IPAddr.new(ARGV[1])
rescue StandardError => e
  puts "Error: #{e}"
end

# Exit if parameters are missing or invalid
exit unless %w(ban unban).include?(command) && ip

def send_request(url, json_data, request_type)
  # Construct our HTTP request
  uri  = URI.parse(url)
  http = Net::HTTP.new(uri.host,
                       uri.port,
                       HTTP_PROXY_SERVER,
                       HTTP_PROXY_PORT,
                       HTTP_PROXY_USERNAME,
                       HTTP_PROXY_PASSWORD)
  http.read_timeout = HTTP_READ_TIMEOUT
  http.use_ssl = true
  request = Net::HTTP::Post.new(uri.request_uri) if request_type == 'POST'
  request = Net::HTTP::Delete.new(uri.request_uri) if request_type == 'DELETE'

  # Add headers for authentication
  request['Content-Type'] = 'application/json'
  request['X-Auth-Email'] = CLOUDFLARE_USERNAME
  request['X-Auth-Key']   = CLOUDFLARE_API_KEY

  request.body = json_data
  http.request(request)
end

def ban_ip(ip)
  # Construct our payload
  data = {}
  data[:mode] = 'challenge'
  data[:configuration] = {}
  data[:configuration][:target] = 'ip'
  data[:configuration][:value] = ip
  data[:notes] = 'Added by Fail2Ban'

  # Perform the POST
  send_request(API_ENDPOINT, data.to_json, 'POST')
end

def unban_ip(id)
  # Construct our payload
  url = "#{API_ENDPOINT}/#{id}"
  # Perform the DELETE
  send_request(url, nil, 'DELETE')
end

ban_ip(ip) if command == 'ban'

if command == 'unban'
  # Ban the IP again to obtain the ID of the record we want to delete
  # This is a tradeoff between storing the ID's locally vs. fetching from
  # CloudFlare
  ban_result = ban_ip(ip)
  result_hash = JSON.parse(ban_result.body)
  id = result_hash['result']['id']
  unban_ip(id)
end
