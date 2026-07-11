#!/usr/bin/env ruby
# frozen_string_literal: true
#
# cloudflare_api_manager.rb
# -------------------------
# Ban / unban an IP address at Cloudflare using IP Access Rules (API v4),
# for use as a fail2ban banaction. Handles IPv4, IPv6 and (Cloudflare-accepted)
# CIDR ranges.
#
# Usage:
#   cloudflare_api_manager.rb ban   <ip>[/<prefix>]
#   cloudflare_api_manager.rb unban <ip>[/<prefix>]
#
# Configuration comes from environment variables, optionally seeded from an
# env file (default /etc/fail2ban/cloudflare.env, override with
# CLOUDFLARE_ENV_FILE). Keep that file owned by root, mode 0600 — it holds
# your credentials, which is why they no longer live in this script.
#
#   CLOUDFLARE_API_TOKEN   Scoped API token (preferred). Send as a Bearer token.
#                          Needs "Zone > Firewall Services > Edit" (zone scope)
#                          or "Account > Firewall Access Rules > Edit".
#   CLOUDFLARE_ZONE_ID     Zone the rule applies to (recommended, least-privilege).
#
#   # Alternative scope, used only when CLOUDFLARE_ZONE_ID is unset:
#   CLOUDFLARE_ACCOUNT_ID  Apply the rule account-wide.
#
#   # Legacy fallback, used only when CLOUDFLARE_API_TOKEN is unset:
#   CLOUDFLARE_EMAIL       Account email      (X-Auth-Email header).
#   CLOUDFLARE_API_KEY     Global API key     (X-Auth-Key header).
#
# Exit status: 0 on success, and also on the harmless no-ops "already banned"
# and "nothing to unban". Non-zero on any real error, so fail2ban can tell a
# ban/unban actually failed.

require 'net/http'
require 'uri'
require 'json'
require 'ipaddr'

API_BASE         = 'https://api.cloudflare.com/client/v4'
DEFAULT_ENV_FILE = '/etc/fail2ban/cloudflare.env'

OPEN_TIMEOUT = 10
READ_TIMEOUT = 15
MAX_RETRIES  = 4   # applied to 429 and 5xx responses and transient socket errors
RETRY_BASE   = 2   # seconds; sleep is RETRY_BASE ** attempt (2, 4, 8, 16)

# Cloudflare accepts only these CIDR prefix lengths for the "ip_range" target.
# Single addresses use "ip"/"ip6" instead and are unaffected.
ALLOWED_V4_PREFIXES = [16, 24].freeze
ALLOWED_V6_PREFIXES = [32, 48, 64].freeze

class Retryable < StandardError; end

def present?(value)
  !value.nil? && !value.to_s.empty?
end

def die(message)
  warn "cloudflare_api_manager: #{message}"
  exit 1
end

# Load config from the env file (if present), then let the real environment
# override it, so an operator can export a variable for a one-off run.
def load_config
  env_file = present?(ENV['CLOUDFLARE_ENV_FILE']) ? ENV['CLOUDFLARE_ENV_FILE'] : DEFAULT_ENV_FILE
  cfg = {}

  if File.file?(env_file)
    File.foreach(env_file) do |line|
      line = line.strip
      next if line.empty? || line.start_with?('#')

      key, _, val = line.partition('=')
      key = key.sub(/\Aexport\s+/, '').strip
      val = val.strip.gsub(/\A["']|["']\z/, '')
      cfg[key] = val unless key.empty?
    end
  end

  %w[CLOUDFLARE_API_TOKEN CLOUDFLARE_ZONE_ID CLOUDFLARE_ACCOUNT_ID
     CLOUDFLARE_EMAIL CLOUDFLARE_API_KEY].each do |k|
    cfg[k] = ENV[k] if present?(ENV[k])
  end

  cfg
end

def auth_headers(cfg)
  if present?(cfg['CLOUDFLARE_API_TOKEN'])
    { 'Authorization' => "Bearer #{cfg['CLOUDFLARE_API_TOKEN']}" }
  elsif present?(cfg['CLOUDFLARE_EMAIL']) && present?(cfg['CLOUDFLARE_API_KEY'])
    { 'X-Auth-Email' => cfg['CLOUDFLARE_EMAIL'], 'X-Auth-Key' => cfg['CLOUDFLARE_API_KEY'] }
  else
    die('no credentials found: set CLOUDFLARE_API_TOKEN (preferred) or ' \
        'CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY in the env file or environment')
  end
end

# Zone scope is preferred; account scope is the alternative; the legacy
# user-level endpoint is the last resort (still works, no longer documented).
def rules_path(cfg)
  if present?(cfg['CLOUDFLARE_ZONE_ID'])
    "/zones/#{cfg['CLOUDFLARE_ZONE_ID']}/firewall/access_rules/rules"
  elsif present?(cfg['CLOUDFLARE_ACCOUNT_ID'])
    "/accounts/#{cfg['CLOUDFLARE_ACCOUNT_ID']}/firewall/access_rules/rules"
  else
    '/user/firewall/access_rules/rules'
  end
end

# Validate the address and derive Cloudflare's target + normalized value.
# Normalizing through IPAddr (lowercase, compressed IPv6) means ban and unban
# send an identical value, so the unban lookup reliably matches the ban.
def target_and_value(raw)
  raw = raw.strip
  has_prefix = raw.include?('/')

  begin
    addr = IPAddr.new(raw)
  rescue IPAddr::Error, ArgumentError
    die("invalid IP address: #{raw.inspect}")
  end

  if has_prefix
    prefix  = raw.split('/', 2).last.to_i
    allowed = addr.ipv4? ? ALLOWED_V4_PREFIXES : ALLOWED_V6_PREFIXES
    unless allowed.include?(prefix)
      family = addr.ipv4? ? 'IPv4' : 'IPv6'
      die("Cloudflare accepts only /#{allowed.join(', /')} for #{family} ranges (got /#{prefix})")
    end
    ['ip_range', "#{addr}/#{prefix}"]
  else
    [addr.ipv4? ? 'ip' : 'ip6', addr.to_s]
  end
end

def http_request(cfg, method, path, query: nil, body: nil)
  uri = URI.parse(API_BASE + path)
  uri.query = URI.encode_www_form(query) if query

  headers = auth_headers(cfg).merge(
    'Content-Type' => 'application/json',
    'Accept'       => 'application/json'
  )
  req_class = { get: Net::HTTP::Get, post: Net::HTTP::Post, delete: Net::HTTP::Delete }.fetch(method)

  attempt = 0
  begin
    attempt += 1
    req = req_class.new(uri.request_uri)
    headers.each { |k, v| req[k] = v }
    req.body = JSON.generate(body) if body

    res = Net::HTTP.start(uri.host, uri.port,
                          use_ssl:      true,
                          open_timeout: OPEN_TIMEOUT,
                          read_timeout: READ_TIMEOUT) { |http| http.request(req) }

    code = res.code.to_i
    raise Retryable, "HTTP #{code}" if (code == 429 || code >= 500) && attempt <= MAX_RETRIES

    parse_response(res)
  rescue Retryable, Errno::ECONNRESET, Errno::ECONNREFUSED, EOFError,
         Net::OpenTimeout, Net::ReadTimeout, SocketError => e
    if attempt <= MAX_RETRIES
      sleep(RETRY_BASE**attempt)
      retry
    end
    die("request to #{path} failed after #{attempt} attempts: #{e.message}")
  end
end

def parse_response(res)
  json =
    if present?(res.body)
      begin
        JSON.parse(res.body)
      rescue JSON::ParserError
        {}
      end
    else
      {}
    end
  { code: res.code.to_i, json: json }
end

def errors_text(resp)
  errs = Array(resp[:json]['errors'])
  return "HTTP #{resp[:code]}" if errs.empty?

  errs.map { |e| "#{e['code']}: #{e['message']}" }.join('; ')
end

def duplicate_error?(json)
  Array(json['errors']).any? { |e| e['message'].to_s =~ /exist|identical|duplicate/i }
end

def ban(cfg, target, value)
  body = {
    mode:          'block',
    configuration: { target: target, value: value },
    notes:         "Added by fail2ban #{Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}"
  }
  resp = http_request(cfg, :post, rules_path(cfg), body: body)

  if resp[:json]['success']
    id = resp[:json].dig('result', 'id')
    puts "banned #{value} (#{target}) -> rule #{id}"
  elsif duplicate_error?(resp[:json])
    puts "already banned #{value} (#{target}); nothing to do"
  else
    die("ban failed for #{value}: #{errors_text(resp)}")
  end
end

def unban(cfg, target, value)
  path = rules_path(cfg)
  resp = http_request(cfg, :get, path, query: {
    'mode'                 => 'block',
    'configuration.target' => target,
    'configuration.value'  => value,
    'per_page'             => 50
  })
  die("unban lookup failed for #{value}: #{errors_text(resp)}") unless resp[:json]['success']

  rules = Array(resp[:json]['result'])
  if rules.empty?
    puts "no active ban found for #{value} (#{target}); nothing to do"
    return
  end

  rules.each do |rule|
    id  = rule['id']
    del = http_request(cfg, :delete, "#{path}/#{id}")
    die("unban delete failed for #{value} (rule #{id}): #{errors_text(del)}") unless del[:json]['success']

    puts "unbanned #{value} -> removed rule #{id}"
  end
end

def main(argv)
  command = argv[0]
  raw     = argv[1]

  unless %w[ban unban].include?(command) && present?(raw)
    die("usage: #{File.basename($PROGRAM_NAME)} ban|unban <ip>[/<prefix>]")
  end

  cfg           = load_config
  target, value = target_and_value(raw)

  case command
  when 'ban'   then ban(cfg, target, value)
  when 'unban' then unban(cfg, target, value)
  end
end

main(ARGV) if $PROGRAM_NAME == __FILE__
