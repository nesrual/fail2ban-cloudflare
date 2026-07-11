# Tests for cloudflare_api_manager.rb
#
# Zero-dependency, framework-free: runnable on any Ruby with
#     ruby test/cloudflare_api_manager_test.rb
# Exits non-zero if any test fails, so it works as a CI gate.
#
# The script defines its helpers as top-level (private Object) methods, so we
# can call them directly here, and the `main` guard keeps it from running on
# require. Net::HTTP is stubbed — no network, no credentials needed.

require 'stringio'
require 'json'
require 'tempfile'
require_relative '../cloudflare_api_manager.rb'

# Make retry/backoff instant.
def sleep(*args)
  nil
end

# ---------------------------------------------------------------------------
# Tiny test harness
# ---------------------------------------------------------------------------
class AssertionError < StandardError; end

$count = 0
$failures = []

def test(name)
  $count += 1
  yield
  print '.'
rescue StandardError => e
  $failures << [name, e]
  print 'F'
end

def assert(cond, msg = 'assertion failed')
  raise AssertionError, msg unless cond
end

def assert_equal(expected, actual)
  assert(expected == actual, "expected #{expected.inspect}, got #{actual.inspect}")
end

def assert_includes(haystack, needle)
  assert(haystack.include?(needle), "#{haystack.inspect} does not include #{needle.inspect}")
end

def assert_raises(klass)
  yield
rescue klass
  # expected
rescue StandardError => e
  raise AssertionError, "expected #{klass}, got #{e.class}: #{e.message}"
else
  raise AssertionError, "expected #{klass} to be raised, but nothing was"
end

def capture_stdout
  old = $stdout
  $stdout = StringIO.new
  yield
  $stdout.string
ensure
  $stdout = old
end

def silence_stderr
  old = $stderr
  $stderr = StringIO.new
  yield
ensure
  $stderr = old
end

# Stub Net::HTTP.start with a fake whose #request records the request and
# returns whatever `responder` produces. Yields the captured-requests array.
def with_http(responder)
  fake = Object.new
  requests = []
  fake.define_singleton_method(:request) do |req|
    requests << req
    responder.call(req)
  end
  original = Net::HTTP.method(:start)
  Net::HTTP.define_singleton_method(:start) { |*_a, **_k, &blk| blk.call(fake) }
  yield requests
ensure
  Net::HTTP.define_singleton_method(:start, original)
end

def fake_res(code, hash)
  res = Net::HTTPResponse.new('1.1', code.to_s, 'msg')
  body = JSON.generate(hash)
  res.define_singleton_method(:body) { body }
  res
end

def token_cfg
  { 'CLOUDFLARE_API_TOKEN' => 'tok', 'CLOUDFLARE_ZONE_ID' => 'z1' }
end

def ok_result(id)
  ->(_req) { fake_res(200, 'success' => true, 'errors' => [], 'result' => { 'id' => id }) }
end

# ---------------------------------------------------------------------------
# target_and_value — address family & CIDR handling (the IPv6 fix)
# ---------------------------------------------------------------------------
test('IPv4 single -> ip target') do
  assert_equal(['ip', '203.0.113.10'], target_and_value('203.0.113.10'))
end

test('IPv6 single -> ip6 target') do
  assert_equal(['ip6', '2001:db8::1'], target_and_value('2001:db8::1'))
end

test('IPv6 is normalized (lowercase, compressed) so unban matches ban') do
  assert_equal(['ip6', '2001:db8::1'], target_and_value('2001:DB8::0:1'))
end

test('IPv4 /24 -> ip_range') do
  assert_equal(['ip_range', '10.0.0.0/24'], target_and_value('10.0.0.0/24'))
end

test('IPv6 /64 -> ip_range') do
  assert_equal(['ip_range', '2001:db8::/64'], target_and_value('2001:db8::/64'))
end

test('IPv4 /25 rejected (Cloudflare allows only /16,/24)') do
  assert_raises(SystemExit) { silence_stderr { target_and_value('10.0.0.0/25') } }
end

test('IPv6 /100 rejected (Cloudflare allows only /32,/48,/64)') do
  assert_raises(SystemExit) { silence_stderr { target_and_value('2001:db8::/100') } }
end

test('garbage address rejected') do
  assert_raises(SystemExit) { silence_stderr { target_and_value('not.an.ip') } }
end

# ---------------------------------------------------------------------------
# auth_headers — token preferred, legacy key fallback
# ---------------------------------------------------------------------------
test('API token -> Bearer auth') do
  assert_equal({ 'Authorization' => 'Bearer tok' }, auth_headers('CLOUDFLARE_API_TOKEN' => 'tok'))
end

test('legacy email+key -> X-Auth headers when no token') do
  headers = auth_headers('CLOUDFLARE_EMAIL' => 'me@x.com', 'CLOUDFLARE_API_KEY' => 'gk')
  assert_equal({ 'X-Auth-Email' => 'me@x.com', 'X-Auth-Key' => 'gk' }, headers)
end

test('no credentials -> hard error') do
  assert_raises(SystemExit) { silence_stderr { auth_headers({}) } }
end

# ---------------------------------------------------------------------------
# rules_path — zone > account > legacy user
# ---------------------------------------------------------------------------
test('zone scope path') do
  assert_equal('/zones/z1/firewall/access_rules/rules', rules_path('CLOUDFLARE_ZONE_ID' => 'z1'))
end

test('account scope path when no zone') do
  assert_equal('/accounts/a1/firewall/access_rules/rules', rules_path('CLOUDFLARE_ACCOUNT_ID' => 'a1'))
end

test('legacy user scope path when neither') do
  assert_equal('/user/firewall/access_rules/rules', rules_path({}))
end

# ---------------------------------------------------------------------------
# load_config — file parsed, env overrides
# ---------------------------------------------------------------------------
test('load_config parses env file and lets real env override it') do
  file = Tempfile.new('cf')
  file.write("# creds\nexport CLOUDFLARE_API_TOKEN=\"filetok\"\nCLOUDFLARE_ZONE_ID=zoneA\n")
  file.close
  saved = ENV.to_hash
  begin
    %w[CLOUDFLARE_API_TOKEN CLOUDFLARE_ZONE_ID CLOUDFLARE_ACCOUNT_ID
       CLOUDFLARE_EMAIL CLOUDFLARE_API_KEY].each { |k| ENV.delete(k) }
    ENV['CLOUDFLARE_ENV_FILE'] = file.path
    ENV['CLOUDFLARE_ZONE_ID']  = 'zoneB' # override the file value
    cfg = load_config
    assert_equal('filetok', cfg['CLOUDFLARE_API_TOKEN']) # from file
    assert_equal('zoneB', cfg['CLOUDFLARE_ZONE_ID'])     # env wins
  ensure
    ENV.replace(saved)
    file.unlink
  end
end

# ---------------------------------------------------------------------------
# ban
# ---------------------------------------------------------------------------
test('ban IPv4 POSTs a block rule to the zone endpoint with Bearer auth') do
  req = nil
  out = capture_stdout do
    with_http(ok_result('r-v4')) do |requests|
      ban(token_cfg, *target_and_value('203.0.113.10'))
      req = requests.first
    end
  end
  assert_includes(out, 'banned 203.0.113.10 (ip)')
  assert_includes(out, 'r-v4')
  assert_equal('POST', req.method)
  assert_includes(req.path, '/zones/z1/firewall/access_rules/rules')
  assert_equal('Bearer tok', req['Authorization'])
  body = JSON.parse(req.body)
  assert_equal('block', body['mode'])
  assert_equal('ip', body['configuration']['target'])
  assert_equal('203.0.113.10', body['configuration']['value'])
end

test('ban IPv6 sends the ip6 target') do
  req = nil
  capture_stdout do
    with_http(ok_result('r-v6')) do |requests|
      ban(token_cfg, *target_and_value('2001:db8::1'))
      req = requests.first
    end
  end
  body = JSON.parse(req.body)
  assert_equal('ip6', body['configuration']['target'])
  assert_equal('2001:db8::1', body['configuration']['value'])
end

test('ban treats a duplicate-rule error as success') do
  dup = ->(_req) { fake_res(400, 'success' => false, 'result' => nil,
                            'errors' => [{ 'code' => 81_019, 'message' => 'firewallaccessrules.api.duplicate_of_existing' }]) }
  out = capture_stdout { with_http(dup) { |_| ban(token_cfg, 'ip', '203.0.113.10') } }
  assert_includes(out, 'already banned')
end

test('ban raises on a real failure') do
  fail_resp = ->(_req) { fake_res(403, 'success' => false, 'result' => nil,
                                  'errors' => [{ 'code' => 9109, 'message' => 'Unauthorized' }]) }
  assert_raises(SystemExit) do
    silence_stderr { with_http(fail_resp) { |_| ban(token_cfg, 'ip', '203.0.113.10') } }
  end
end

# ---------------------------------------------------------------------------
# unban — GET by IP value, then DELETE by id (no local state file)
# ---------------------------------------------------------------------------
test('unban looks the rule up by IP then deletes it') do
  responder = lambda do |req|
    if req.method == 'GET'
      fake_res(200, 'success' => true, 'errors' => [], 'result' => [{ 'id' => 'ru-1' }])
    else
      fake_res(200, 'success' => true, 'errors' => [], 'result' => { 'id' => 'ru-1' })
    end
  end
  reqs = nil
  out = capture_stdout do
    with_http(responder) do |requests|
      unban(token_cfg, *target_and_value('203.0.113.10'))
      reqs = requests
    end
  end
  assert_includes(out, 'unbanned 203.0.113.10')
  assert_equal('GET', reqs[0].method)
  assert_includes(reqs[0].path, 'configuration.value=203.0.113.10')
  assert_equal('DELETE', reqs[1].method)
  assert_includes(reqs[1].path, '/access_rules/rules/ru-1')
end

test('unban is a no-op when no matching rule exists') do
  none = ->(_req) { fake_res(200, 'success' => true, 'errors' => [], 'result' => []) }
  reqs = nil
  out = capture_stdout do
    with_http(none) do |requests|
      unban(token_cfg, 'ip', '198.51.100.7')
      reqs = requests
    end
  end
  assert_includes(out, 'no active ban found')
  assert_equal(1, reqs.length) # GET only, no DELETE
end

test('unban raises when the lookup fails') do
  bad = ->(_req) { fake_res(403, 'success' => false, 'errors' => [{ 'code' => 9109, 'message' => 'Unauthorized' }]) }
  assert_raises(SystemExit) do
    silence_stderr { with_http(bad) { |_| unban(token_cfg, 'ip', '203.0.113.10') } }
  end
end

# ---------------------------------------------------------------------------
# retry/backoff
# ---------------------------------------------------------------------------
test('a 429 is retried and then succeeds') do
  calls = 0
  responder = lambda do |_req|
    calls += 1
    if calls == 1
      fake_res(429, 'success' => false, 'errors' => [])
    else
      fake_res(200, 'success' => true, 'errors' => [], 'result' => { 'id' => 'r1' })
    end
  end
  capture_stdout { with_http(responder) { |_| ban(token_cfg, 'ip', '203.0.113.10') } }
  assert_equal(2, calls)
end

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
puts
if $failures.empty?
  puts "#{$count} tests, all passed"
else
  $failures.each { |(name, err)| puts "\nFAIL: #{name}\n  #{err.class}: #{err.message}" }
  puts "\n#{$failures.size} of #{$count} tests failed"
  exit 1
end
