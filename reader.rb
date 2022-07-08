#!/bin/env ruby
## 

require 'pry'

input = './password_backup'

contents = File.read(input)

results = Array.new

contents.split("\n").each do |line|
  tokens = line.split(/\s/)[1..8]

  tokens.each do |t|
    t.scan(/\w\w/).each do |tt|
      
      results << tt.to_i(16).chr
    end
  end

end

output = sprintf('%s.out', input)

File.open(output, 'w') do |f|
  f.write(results.join(''))
end



binding.pry
