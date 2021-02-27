require 'net/https'
require 'uri'
require 'json'
require 'ipaddr'

# Various settings
API_ENDPOINT = 'https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules'.freeze
CLOUDFLARE_USERNAME     = 'YOUR_CLOUDFLARE_USERNAME_GOES_HERE'.freeze
CLOUDFLARE_API_KEY      = 'YOUR_API_KEY_GOES_HERE'.freeze

# Store banned IP'send_request
BANNED_TXT = 'cb_ban.txt'.freeze

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
  data[:mode] = 'block'
  data[:configuration] = {}
  data[:configuration][:target] = 'ip'
  data[:configuration][:value] = ip
  data[:notes] = 'Added by Fail2Ban'

  # Perform the POST
  response = send_request(API_ENDPOINT, data.to_json, 'POST')
  ban_id = JSON.parse(response.body)['result']['id']
  
  # Store the new banned IP on cf_ban.txt
  File.open(BANNED_TXT, "a") { |f| f.write "#{ip}:#{ban_id}\n" }
end

def unban_ip(id)
  # Construct our payload
  data = {}
  # Encode URL
  url = URI.encode("#{API_ENDPOINT}/#{id}")
  url.gsub!(/%0A/, "")
  # Perform the DELETE
  send_request(url, data.to_json, 'DELETE')
end

ban_ip(ip) if command == 'ban'

if command == 'unban'
  # Get token ID of the banned IP from cf_ban.txt
    File.open(BANNED_TXT, "r+") do |f|
    f.each_line do |line|
    if line =~ /#{ip}/
        key,value = line.split(":")
        # Send token ID to CloudFlare API.
        unban_ip(value)
        # Remove banned IP from cf_ban.txt
        f.seek(-line.length, IO::SEEK_CUR)
        f.write(' ' * (line.length - 1))
    end
    end
    f.close
    end
end
