import requests
import json
from bs4 import BeautifulSoup


def VulnCheck(url, count):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    amogus = soup.find_all('tr')
    
    for item in amogus[1:]:
        item3 = item.find_all('td')
        if 'No' in ''.join(item3[4]):
            if count != 0:
                file.write(',\n')
            item2 = item.find_all('a')
            if 'LOW' in str(item3[3]):
                severity = "low"
            elif 'MODERATE' in str(item3[3]):
                severity = "medium"
            elif 'HIGH' in str(item3[3]):
                severity = "high"
            elif 'CRITICAL' in str(item3[3]):
                severity = "critical"
            else:
                severity = "Not defined"

            vuln = {
                "vulnlink": f'{item2[0].attrs['href']}',
                "liblink": f'{item2[1].attrs['href']}',
                "severity": severity,
                "lib": str(item2[1]).split('>')[1][:-3],
                "issue": str(item2[0]).split('>')[1][:-3]
            }
            
            json.dump(vuln, file, indent=4)
            count += 1
    
    return count


def MaxPages(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    mydivs = soup.find_all("div", {"class": "text-left mt-1"})

    for i in mydivs:
        pages = i.find_all('b')
        maxpages = int(''.join(filter(str.isdigit, str(pages[1]))))
    
    return maxpages



file = open('libs.json', 'w')
file.write('[')

count = 0

url = 'https://vulert.com/vuln-db/search?q=&vulnerabilities[]=PyPI'
print("page 1")
count = VulnCheck(url, count)
maxpages = MaxPages(url)

for page in range(2, maxpages+1):
    print(f"page {page}")
    url2 = f"https://vulert.com/vuln-db/search?vulnerabilities%5B0%5D=PyPI&page={page}"
    count = VulnCheck(url2, count)

file.write("]")
file.close()