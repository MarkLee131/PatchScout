import gc
import git
import glob
import logging
import os
import shutil
import pandas as pd
from collections import Counter
import json
from utils import *

features_columns = ['cve_match', 'bug_match', # VI
                    'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt', # VL
                    'file_same_cnt', 'file_same_ratio', 'file_unrelated_cnt', # VL
                    'vuln_type_1', 'vuln_type_2', 'vuln_type_3', 'patchlike',  # VT
                    'mess_shared_num', 'mess_shared_ratio', 'mess_max', 'mess_sum', 'mess_mean', 'mess_var', # VDT
                    'code_shared_num', 'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var'] # VDT

# def get_feature(row, commit_info):
#     commit = row['commit']
#     bug, issue, cve = commit_info[commit]
#     issue_cnt, web_cnt, bug_cnt, cve_cnt = weblinks_bug_issue_cve(
#         bug, issue, cve, row)
#     return issue_cnt, web_cnt, bug_cnt, cve_cnt


def file_match_func(filepaths, funcs, desc):
    files = [path.split('/')[-1] for path in filepaths]
    file_match = As_in_B(files, desc)
    filepath_match = As_in_B(filepaths, desc)
    func_match = As_in_B(funcs, desc)
    return file_match, filepath_match, func_match


def get_vuln_loc(nvd_items, commit_items):
    # ['dashdec.c'], ['b/libavformat/dashdec.c']
    same_cnt = 0
    for commit_item in commit_items:
        for nvd_item in nvd_items:
            if nvd_item in commit_item:
                same_cnt += 1
                break
    if len(commit_items) == 0:
        same_ratio = 0
    else:
        same_ratio = same_cnt / (len(commit_items))
        
    unrelated_cnt = len(nvd_items) - same_cnt
    return same_cnt, same_ratio, unrelated_cnt


def get_vuln_type_relevance(nvd_type, nvd_impact, commit_type, commit_impact,
                         vuln_type_impact):
    l1, l2, l3 = 0, 0, 0
    for nvd_item in nvd_type:
        for commit_item in commit_type:
            if nvd_item == commit_item:
                l1 += 1
            else:
                l3 += 1

    for nvd_item in nvd_type:
        for commit_item in commit_impact:
            if commit_item in vuln_type_impact.get(nvd_item):
                l2 += 1
            else:
                l3 += 1

    for commit_item in commit_type:
        for nvd_item in nvd_impact:
            if nvd_item in vuln_type_impact.get(commit_item):
                l2 += 1
            else:
                l3 += 1
    cnt = l1 + l2 + l3 + 1
    return l1 / cnt, l2 / cnt, (l3 + 1) / cnt


def get_vuln_idf(bug, links, cve, cves):
    cve_match = 0
    for item in cves:
        if item in cve.lower():
            cve_match = 1
            break

    bug_match = 0
    for link in links:
        if 'bug' in link or 'Bug' in link:
            for item in bug:
                if item.lower() in link:
                    bug_match = 1
                    break

    return bug_match, cve_match


# c1 # nvd
# c2 # code
def get_VDT(c1, c2):
    c3 = c1 and c2
    same_token = c3.keys()
    shared_num = len(same_token)
    shared_ratio = shared_num / (len(c1.keys()) + 1)
    c3_value = list(c3.values())
    if len(c3_value) == 0:
        c3_value = [0]
    return shared_num, shared_ratio, max(c3_value), sum(c3_value), np.mean(
        c3_value), np.var(c3_value)




if __name__ == '__main__':
    # cve,commit_id,commit_msg,diff,label
    diff = pd.read_csv('/home/kaixuan_cuda11/patchmatch/analyze/PatchScout/data/csv_data/drop_diffna.csv',chunksize=1000)
    for chunk in diff:
        for index, row in chunk.iterrows():
            row['commit_msg'] = row['commit_msg']