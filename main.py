import requests
import json
import sys
from bs4 import BeautifulSoup

import codechecker


def DirViewer(url, list, level):
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

        filename = '/'.join(url.split('/')[8:])

        LibChecker(response.text, filename, reportlist)
        
        CodeChecker(response.text, filename, reportlist)


def LibChecker(text, filename, reportlist):
    with open('libs.json', 'r') as file:
        libsdata = json.loads(file.read())
        for rep in libsdata:
            if str(f"import {rep['lib']}") in text:
                report = {
                    'filename': filename,
                    'code': f"Affected library: {rep['lib']} ",
                    'issue': rep['issue'],
                    'severity': rep['severity'],
                    'confidence': "high",
                    'link': f"\nIssue link: {rep['vulnlink']}\nPrevious vulnerabilities info: {rep['liblink']}"
                }
                reportlist.append(report)


def CodeChecker(text, filename, reportlist):
    
    data = codechecker.parse(text)

    for rep in data:
        report = {
            'filename': filename,
            'code': '',
            'issue': rep['text'],
            'severity': rep['severity'],
            'confidence': rep['confidence'],
            'link': rep['cwe']
        }
        reportlist.append(report)



url = sys.argv[1]
tree = sys.argv[2]
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
    FileChecker(rawlink, reportlist)

for report in reportlist:
    print(f'Issue in file: {report['filename']}')
    print(report['code'][:-1])
    print(f'Issue: {report['issue']}')
    print(f'Severity: {report['severity']}')
    print(f'Severity: {report['severity']}')
    print(f'More info: {report['link']}\n')
