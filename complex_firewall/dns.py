import socket

def get_ip_address(domain):
  try:
    ip_addresses = socket.gethostbyname_ex(domain)[2]
    # Use first IP Address for simplicity
    return ip_addresses[0]
  except socket.gaierror as e:
    print(f"Error resolving {domain}: {e}")
    return []

# Mostly taken from https://en.wikipedia.org/wiki/List_of_most-visited_websites
most_popular_sites = [
  "google.com",
  "youtube.com",
  "facebook.com",
  "instagram.com",
  "x.com",
  "baidu.com",
  "wikipedia.org",
  "yahoo.com",
  "yandex.ru",
  "whatsapp.com",
  "amazon.com",
  "tiktok.com",
  "live.com",
  "yahoo.co.jp",
  "reddit.com",
  "openai.com",
  "docomo.ne.jp",
  "linkedin.com",
  "office.com",
  "netflix.com",
  "dzen.ru",
  "bing.com",
  "bilibili.com",
  "samsung.com",
  "mail.ru",
  "naver.com",
  "vk.com",
  "pinterest.com",
  "max.com",
  "microsoft.com",
  "discord.com",
  "turbopages.org",
  "weather.com",
  "twitch.tv",
  "zoom.us",
  "t.me",
  "qq.com",
  "duckduckgo.com",
  "quora.com",
  "sharepoint.com",
  "globo.com",
  "ebay.com",
  "fandom.com",
  "princeton.edu",
  "cnn.com",
  "spotify.com",
  "chegg.com",
  "123movies.to",
  "washingtonpost.com",
  "hulu.com"
]

sites_to_ip = {}
list_of_ips = []

for site in most_popular_sites:
  sites_to_ip[site] = get_ip_address(site)
  list_of_ips.append(sites_to_ip[site])