# Run with: rake         (default task runs the tests)
#           rake test    (explicit)
#           rake lint    (syntax check the manager script)
#
# The suite is framework-free, so you can also run it without rake:
#           ruby test/cloudflare_api_manager_test.rb

task default: %i[lint test]

desc 'Run the test suite'
task :test do
  sh 'ruby', 'test/cloudflare_api_manager_test.rb'
end

desc 'Syntax-check the manager script'
task :lint do
  sh 'ruby', '-c', 'cloudflare_api_manager.rb'
end
