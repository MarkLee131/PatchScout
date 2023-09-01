import re
import re
import string
import warnings
import string
import json
import pandas as pd
from nltk.corpus import stopwords
# from utils import *
warnings.filterwarnings("ignore")

stopword_list = stopwords.words('english') + list(string.punctuation)

# =============== vuln_data ===============

def re_filepath(item):
    res = []
    find = re.findall(
        '(([a-zA-Z0-9]|-|_|/)+\.(cpp|cc|cxx|cp|CC|hpp|hh|C|c|h|py|php|java))',
        item)
    for item in find:
        res.append(item[0])
    return res


def re_file(item):
    res = []
    find = re.findall(
        '(([a-zA-Z0-9]|-|_)+\.(cpp|cc|cxx|cp|CC|hpp|hh|C|c|h|py|php|java))',
        item)
    for item in find:
        res.append(item[0])
    return res


def re_func(item):
    res = []
    find = re.findall("(([a-zA-Z0-9]+_)+[a-zA-Z0-9]+.{2})", item)
    for item in find:
        item = item[0]
        if item[-1] == ' ' or item[-2] == ' ':
            res.append(item[:-2])

    find = re.findall("(([a-zA-Z0-9]+_)*[a-zA-Z0-9]+\(\))", item)
    for item in find:
        item = item[0]
        res.append(item[:-2])

    find = re.findall("(([a-zA-Z0-9]+_)*[a-zA-Z0-9]+ function)", item)
    for item in find:
        item = item[0]
        res.append(item[:-9])
    return res

def get_tokens(text, List):
    return set([item for item in List if item in text])




if __name__ == '__main__':
    ### 03.30
    with open("/home/kaixuan/locating_patch/analyze/PatchScout/data/vuln_type_impact.json", 'r') as f:
        vuln_type_impact = json.load(f)
    
    vuln_type = set(vuln_type_impact.keys())
    vuln_impact = set()
    for value in vuln_type_impact.values():
        vuln_impact.update(value)

    df = pd.read_csv("/home/kaixuan/locating_patch/analyze/total_data/cve_info/cve_desc.csv")
    # cve, cvedesc
    
    
    df['functions'] = df['cvedesc'].apply(re_func)
    df['files'] = df['cvedesc'].apply(re_file)
    df['filepaths'] = df['cvedesc'].apply(re_filepath)
    df['vuln_type'] = df['cvedesc'].apply(lambda item: get_tokens(item, vuln_type))
    df['vuln_impact'] = df['cvedesc'].apply(lambda item: get_tokens(item, vuln_impact))
    # df.drop(['owner','repo'], axis=1, inplace=True)
    df.to_csv("/home/kaixuan/locating_patch/analyze/total_data/cve_info/vuln_data.csv", index=False)
    print("Done for saving vuln_data.csv.")
    # cve,cvedesc, functions,files,filepaths,vuln_type,vuln_impact

'''
TO run this script, you need to first obtain the vuln_data.csv.
Then steps is:
1. run this script
2. code_data.py
3. msg_data.py
4. commit_data.py
'''

