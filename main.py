import requests
import json
from subprocess import Popen, PIPE
from bs4 import BeautifulSoup


def DirViewer(url, list, level):
    with open('logs.txt', 'a') as logs:
        newurl = 'https://github.com' + url
        response = requests.get(newurl)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.select('a.Link--primary')
        links = set(links)
        level+=1

        for link in links:
            word = link.attrs['href'].split('/')
            if word[3] == 'tree':
                DirViewer(link.attrs['href'], list, level)
            else:
                result = '/'.join(word[-(level):])
                urlraw = 'https://raw.githubusercontent.com/' + owner + '/' + repo + '/refs/heads/' + tree + '/' + result
                list.append(urlraw)
    return list


def FileChecker(url, reportlist):
    if url.split('/')[-1][-3:] == '.py':
        response = requests.get(url)
        print(response.status_code)

        file = open('tmp.py', 'w', encoding="utf-8")
        file.write(response.text)
        file.close()
        filename = '/'.join(url.split('/')[8:])

        BanditModule(filename, reportlist)


def BanditModule(filename, reportlist):
    p = Popen(['python', 'bandit/cli/main.py', '-f', 'json', 'tmp.py'], stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)
    stdout, _ = p.communicate()

    data = json.loads(stdout)

    for rep in data['results']:
        report = {
            'filename': filename,
            'code': rep['code'],
            'issue': rep['issue_text'],
            'severity': rep['issue_severity'],
            'link': rep['issue_cwe']['link']
        }
        reportlist.append(report)



url = argv[1]
tree = argv[2]
owner = url.split('/')[3]
repo = url.split('/')[4]

urlstart = '/' + owner + '/' + repo + '/tree/' + tree

response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')
links = soup.select('a.Link--primary')
links = set(links)
rawlinks = []
for link in links:
    word = link.attrs['href'].split('/')
    if word[3] == 'tree':
        DirViewer(link.attrs['href'], rawlinks, 1)
    else:
        result = ''.join(word[-1:])
        urlraw = 'https://raw.githubusercontent.com/' + owner + '/' + repo + '/refs/heads/' + tree + '/' + result
        rawlinks.append(urlraw)

reportlist = []
for rawlink in rawlinks:
    print(rawlink)
    FileChecker(rawlink, reportlist)

for report in reportlist:
    print(f'Issue in file: {report['filename']}')
    print(report['code'][:-1])
    print(f'Issue: {report['issue']}')
    print(f'Severity: {report['severity']}')
    print(f'More info: {report['link']}\n')
