#!/usr/bin/env ruby

require 'net/http'
require 'uri'
require 'cgi'

# Fungsi untuk memeriksa kerentanan XSS pada URL yang diberikan
def check_xss_vulnerability(url)
  uri = URI.parse(url)
  response = Net::HTTP.get_response(uri)
  body = response.body

  # Pola-pola XSS yang dicari
  xss_patterns = [
    /<script.*?>.*?<\/script>/i,        # Tag <script>
    /on\w+=".*?"/i,                     # Handler event (misal: onclick)
    /<a\s+href="javascript:.*?"/i,      # Protocol javascript:
    /<iframe.*?>.*?<\/iframe>/i,        # Tag <iframe>
    /<img.*?src="javascript:.*?"/i,     # Protocol javascript: dalam tag <img>
    /<svg.*?<script>.*?<\/script>/i     # Tag <script> dalam SVG
  ]

  # Array untuk menyimpan potongan kode yang berpotensi XSS
  vulnerable_snippets = []

  # Melakukan pencarian dengan regex untuk setiap pola
  xss_patterns.each do |pattern|
    body.scan(pattern) do |match|
      vulnerable_snippets << match
    end
  end

  return vulnerable_snippets
end

# Program utama
loop do
  puts "\nXSS Vulnerability Checker"
  puts "========================="
  puts "Menu:"
  puts "1. Mulai Scan XSS"
  puts "2. Keluar"
  print "Pilih menu (1/2): "
  choice = gets.chomp.strip

  case choice
  when '1'
    puts "\nMasukkan URL target (contoh: http://example.com):"
    url = gets.chomp.strip

    if url.empty?
      puts "URL tidak boleh kosong. Silakan coba lagi."
      next
    end

    # Memeriksa kerentanan XSS
    vulnerable_snippets = check_xss_vulnerability(url)

    if vulnerable_snippets.empty?
      puts "Tidak ditemukan kerentanan XSS pada URL: #{url}"
    else
      puts "Ditemukan potensi kerentanan XSS pada URL: #{url}"

      # Menyimpan potongan HTML yang berpotensi XSS ke file result.txt
      File.open("result.txt", "w") do |file|
        file.puts "Potongan HTML yang berpotensi XSS:\n\n"
        vulnerable_snippets.each do |snippet|
          file.puts snippet
          file.puts "\n"
        end
      end

      puts "Potongan HTML yang berpotensi XSS telah disimpan di file: result.txt"
    end

  when '2'
    puts "Terima kasih telah menggunakan XSS Vulnerability Checker."
    break

  else
    puts "Pilihan tidak valid. Silakan pilih 1 atau 2."
  end
end
