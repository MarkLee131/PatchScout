import time
import logging as lg
import re
import requests
import pandas as pd
from tqdm import tqdm
from bs4 import BeautifulSoup, NavigableString # pip install beautifulsoup4
# the env also needs to install lxml;
from utils import *

headers={
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
    # "Cookie": "" 
}


def clean_cwe(cwe):
    cwe_pattern = r"CWE-(\d+)"
    match = re.search(cwe_pattern, cwe)
    if match:
        return match.group(0)
    else:
        return 'NVD-CWE-Other'


def get_nvd_info(cve):
    page = 'https://nvd.nist.gov/vuln/detail/'+cve
    links = []
    cwe = ()
    res = requests.get(url=page,  headers=headers)
    while (res.status_code != 200):
        time.sleep(5) # Prevent frequent visits
        res = requests.get(url=page,  headers=headers)
    try:
        soup = BeautifulSoup(res.text, 'lxml')
        tbody = soup.find(attrs={'data-testid': "vuln-hyperlinks-table"}).tbody
        for tr in tbody.children:
            if isinstance(tr, NavigableString): continue
            tds = tr.findAll('td')
            if 'Patch' in tds[1].text:
                links.append(tds[0].a['href'])
        tbody = soup.find(attrs={'data-testid': "vuln-CWEs-table"}).tbody
        for tr in tbody.children:
            if isinstance(tr, NavigableString): continue
            tds = tr.findAll('td')
            # cwe = (tds[0].text, tds[1].text)
            cwe = (clean_cwe(tds[0].text), tds[1].text)
    except Exception as e:
    # time.sleep(5) # Prevent frequent visits
        print(page, e)
    return cve, links, cwe




if __name__ == '__main__':

    # ### cve,commit_id,commit_msg,diff,label
    # df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/cve_info.csv')
    # cve_list = df.cve.unique()
    # ### get nvd info
    # result_list = []
    # for cve in tqdm.tqdm(cve_list):
    #     cve, links, cwe = get_nvd_info(cve)
    #     result_list.append([cve, links, cwe])
    # df1 = pd.DataFrame(result_list, columns=['cve', 'links', 'cwe'])
    # df1 = df1.drop_duplicates(['cve']).reset_index(drop=True)
    # df1.to_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/cve_nvd.csv", index = False)
    
    # cve, links, cwe = get_nvd_info('CVE-2010-2060')
    # print([cve, links, cwe])
    
    df1 = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/cve_nvd.csv")
    df2 = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/vuln_data.csv")
    df3 = df2.merge(df1[['cve', 'links']], how='left', on='cve')
    df3.to_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/vuln_data-1.csv", index = False)