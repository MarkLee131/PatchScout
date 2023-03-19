import re
import os
import warnings
import git
import pandas as pd
from tqdm import tqdm
from multiprocessing import Pool
from utils import *
warnings.filterwarnings("ignore")


def get_info(cve, commit_id, commit_msg, diff):
    # data to be collected
    weblinks, bug, issue, cve = [], [], [], []
    filepaths, funcs = [], []
    # get weblink bugID issueID cveID
    link_re = r'https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]'
    weblinks.extend(re.findall(link_re, commit_msg))
    bug.extend(re.findall('[bB]ug[^0-9]{0,5}([0-9]{1,7})[^0-9]', commit_msg))
    issue.extend(re.findall('[iI]ssue[^0-9]{0,5}([0-9]{1,7})[^0-9]', commit_msg))
    cve.extend(re.findall('[CVEcve]{3}-[0-9]+-[0-9]+', commit_msg))
    
    lines = diff.split('\n')
    for line in lines:
        # get weblink bugID issueID cveID in code diff
        weblinks.extend(re.findall(link_re, line))
        bug.extend(re.findall('[bB]ug[^0-9]{0,5}([0-9]{1,7})[^0-9]', line))
        issue.extend(re.findall('[iI]ssue[^0-9]{0,5}([0-9]{1,7})[^0-9]', line))
        cve.extend(re.findall('[CVEcve]{3}-[0-9]+-[0-9]+', line))
        # get filepaths and funcnames in code diff
        if line.startswith('diff --git'):
            filepath = line.split(' ')[-1].strip()[2:]
            filepaths.append(filepath)
        elif line.startswith('@@ '):
            funcname = line.split('@@')[-1].strip()
            funcname = funcs_preprocess(funcname)
            funcs.append(funcname)

    return [cve, commit_id, set(weblinks), set(bug), set(issue), set(cve), set(filepaths), set(funcs)]


def get_commit_info(data):
    return get_info(*data)


def multi_process_get_commit_info(cve_ids, commit_ids, msgs, diffs, poolnum=5):
    length = len(cve_ids)
    with Pool(poolnum) as p:
        ret = list(tqdm.tqdm(p.imap(get_commit_info, zip(cve_ids, commit_ids, msgs, diffs)), total=length, desc='get commits info'))
        p.close()
        p.join()
    return ret

if __name__ == '__main__':
##### maybe unuseful...


    df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/drop_diffna.csv")
    df = reduce_mem_usage(df)
    
    commit_savepath = '/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/msg_data.csv'
    cve_ids = df['cve'].tolist()
    commit_ids = df['commit_id'].tolist()
    msgs = df['commit_msg'].tolist()
    diffs = df['diff'].tolist()
    msg_len = len(msgs)
    commit_data = multi_process_get_commit_info(cve_ids, commit_ids, msgs, diffs, poolnum=10)
    
    commit_df = pd.DataFrame(commit_data,
                                columns=['cve_id', 'commit_id', 'weblinks', 'bug', 'issue_cnt', 'cve', 'filepaths', 'funcs'])
    
    commit_df.to_csv(commit_savepath, index=False)
