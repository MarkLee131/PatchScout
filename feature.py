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

gitpath = "/home/kaixuan_cuda11/patch_match/analyze/VCMatch/gitrepo/"


def weblinks_bug_issue_cve(weblinks, bug, issue, cve, row):
    issue_cnt = len(issue)
    web_cnt = len(weblinks)
    bug_cnt = len(bug)
    cve_cnt = len(cve)
    return issue_cnt, web_cnt, bug_cnt, cve_cnt


def file_match_func(filepaths, funcs, desc):
    files = [path.split('/')[-1] for path in filepaths]
    file_match = As_in_B(files, desc)
    filepath_match = As_in_B(filepaths, desc)
    func_match = As_in_B(funcs, desc)
    return file_match, filepath_match, func_match


def vuln_commit_token(reponame, commit, cwedesc_tokens, desc_tokens):
    vuln_tokens = union_list(desc_tokens, cwedesc_tokens)

    with open('../data/gitcommit/{}/{}'.format(reponame, commit), 'r') as fp:
        commit_tokens = eval(fp.read())

    commit_tokens_set = set(commit_tokens)

    inter_token_total = inter_token(set(vuln_tokens), commit_tokens_set)
    inter_token_total_cnt = len(inter_token_total)
    inter_token_total_ratio = inter_token_total_cnt / len(vuln_tokens)

    inter_token_cwe = inter_token(set(cwedesc_tokens), commit_tokens_set)
    inter_token_cwe_cnt = len(inter_token_cwe)
    inter_token_cwe_ratio = inter_token_cwe_cnt / (1 + len(cwedesc_tokens))

    return vuln_tokens, commit_tokens, inter_token_total_cnt, inter_token_total_ratio, inter_token_cwe_cnt, inter_token_cwe_ratio


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


def get_vuln_loc(nvd_items, commit_items):
    same_cnt = 0
    for commit_item in commit_items:
        for nvd_item in nvd_items:
            if nvd_item in commit_item:
                same_cnt += 1
                break
    same_ratio = same_cnt / (len(commit_items) + 1)
    unrelated_cnt = len(nvd_items) - same_cnt
    return same_cnt, same_ratio, unrelated_cnt


def get_vuln_type_relete(nvd_type, nvd_impact, commit_type, commit_impact,
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


# c1 # nvd
# c2 # code


def get_vuln_desc_text(c1, c2):
    c3 = c1 and c2
    same_token = c3.keys()
    shared_num = len(same_token)
    shared_ratio = shared_num / (len(c1.keys()) + 1)
    c3_value = list(c3.values())
    if len(c3_value) == 0:
        c3_value = [0]
    return shared_num, shared_ratio, max(c3_value), sum(c3_value), np.mean(
        c3_value), np.var(c3_value)


def get_feature(row, commit_info):
    commit = row['commit']
    bug, issue, cve = commit_info[commit]
    issue_cnt, web_cnt, bug_cnt, cve_cnt = weblinks_bug_issue_cve(
        bug, issue, cve, row)
    return issue_cnt, web_cnt, bug_cnt, cve_cnt


if __name__ == '__main__':

    dataset_df = pd.read_csv("../data/Dataset_5000.csv")
    dataset_df = reduce_mem_usage(dataset_df)

    commit_df = pd.read_csv("../data/patchlikehood-1.csv")
    commit_df = reduce_mem_usage(commit_df)
    
    ### when running: need to change to data.csv   
    vuln_df = pd.read_csv('../data/vuln_data-1.csv')  
    vuln_df['desc'] = vuln_df['desc'].apply(eval)
    vuln_df['cwedesc'] = vuln_df['cwedesc'].apply(eval)
    vuln_df['functions'] = vuln_df['functions'].apply(eval)
    vuln_df['files'] = vuln_df['files'].apply(eval)
    vuln_df['filepaths'] = vuln_df['filepaths'].apply(eval)
    vuln_df['vuln_type'] = vuln_df['vuln_type'].apply(eval)
    vuln_df['vuln_impact'] = vuln_df['vuln_impact'].apply(eval)
    vuln_df = reduce_mem_usage(vuln_df)
    mess_df = pd.read_csv("../data/mess_data.csv")
    mess_df['mess_bugs'] = mess_df['mess_bugs'].apply(eval)
    mess_df['mess_cves'] = mess_df['mess_cves'].apply(eval)
    mess_df['mess_type'] = mess_df['mess_type'].apply(eval)
    mess_df['mess_impact'] = mess_df['mess_impact'].apply(eval)

    commit_df['patchlike'] = commit_df['patchlike'].astype(float)
    commit_df['commit'] = commit_df['commit'].astype(str)

    dataset_df = (dataset_df.merge(vuln_df, how='left', on='cve').merge(
        commit_df, how='left', on='commit').merge(mess_df,
                                                  how='left',
                                                  on='commit'))

    # dataset_df = (dataset_df.merge(vuln_df, how='left', on='cve').
    #               merge(commit_df['commit', 'patchlike'], how='left', on='commit').
    #               merge(mess_df, how='left', on='commit'))

    dataset_df.fillna(0.5)
    del vuln_df, commit_df
    gc.collect()

    repos = dataset_df.repo.unique()
    for reponame in repos:
        print('当前时间为', time.strftime("%H:%M:%S"))
        dirpath = '../data/tmp/' + reponame
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)
        tmp_df = dataset_df[dataset_df.repo == reponame]
        repo = git.Repo(gitpath + reponame)
        commits = tmp_df.commit.unique()
        commit_info = readfile(
            '../data/commit_info/{}_commit_info'.format(reponame))

        total_cnt = tmp_df.shape[0]
        each_cnt = 1000
        epoch = int((total_cnt + each_cnt) / each_cnt)
        logging.info('共有{}个epoch'.format(epoch))

        t1 = time.time()
        # batch process
        for i in tqdm.tqdm(range(epoch)):
            if os.path.exists(dirpath + '/{:04}.csv'.format(i)):
                continue
            df = tmp_df.iloc[i * each_cnt:min((i + 1) * each_cnt, total_cnt)]
            df["addcnt"], df["delcnt"], df["issue_cnt"], df["web_cnt"], df[
                "bug_cnt"], df["cve_cnt"] = zip(*df.apply(
                    lambda row: get_feature(row, commit_info), axis=1))
            df['totalcnt'] = df["addcnt"] + df["delcnt"]

            # kaixuan: desc2 is not defined, so I comment it and delete it.
            # df.drop(['desc', 'links', 'cwedesc', 'cvetime',
            #          'desc2'], axis=1, inplace=True)
            df.drop(['desc', 'links', 'cwedesc', 'cvetime'],
                    axis=1,
                    inplace=True)
            df.to_csv(dirpath + '/{:04}.csv'.format(i), index=False)
        t2 = time.time()
        logging.info('{}共耗时：{} min'.format(reponame, (t2 - t1) / 60))
        gc.collect()

        files = glob.glob(dirpath + '/*.csv')
        m = {}
        for file in files:
            idx = int(re.search('([0-9]+).csv', file).group(1))
            m[idx] = file

        l = []
        for i in range(1, epoch):
            tmp = pd.read_csv(m[i])
            l.append(tmp)

        data_df = pd.concat(l)
        data_df.to_csv('../data/Dataset_feature.csv')

        # shutil.rmtree(dirpath)

        logging.info("")

        # print('当前时间为', time.strftime("%H:%M:%S"))
        dirpath = '../data/tmp_ps/' + reponame

        if not os.path.exists(dirpath):
            os.makedirs(dirpath)
        # print(reponame+"正在处理")

        code_df = pd.read_csv(
            "../data/code_data/code_data_{}.csv".format(reponame))
        # "commit,code_files, code_filepaths, code_funcs, code_token_counter"
        
        code_df['code_files'] = code_df['code_files'].apply(eval)
        code_df['code_funcs'] = code_df['code_funcs'].apply(eval)
        code_df['code_filepaths'] = code_df['code_filepaths'].apply(eval)

        code_df['code_token_counter'] = code_df['code_token_counter'].apply(
            lambda x: eval(x) if isinstance(x, str) else x)

        tmp_df = dataset_df[dataset_df.repo == reponame]
        tmp_df = (tmp_df.merge(code_df, how='left', on='commit'))  # .
        #   merge(mess_df, how='left', on='commit'))
        commits = tmp_df.commit.unique()

        total_cnt = tmp_df.shape[0]
        each_cnt = 2000
        epoch = int((total_cnt + each_cnt) / each_cnt)
        logging.info('共有{}个epoch'.format(epoch))

        vuln_type_impact = json.load(open('../data/vuln_type_impact.json'))

        t1 = time.time()
        for i in tqdm.tqdm(range(epoch)):
            if os.path.exists(dirpath + '/{:04}.csv'.format(i)):
                continue
            df = tmp_df.iloc[i * each_cnt:min((i + 1) * each_cnt, total_cnt)]
            df['cve_match'], df['bug_match'] = zip(
                *df.apply(lambda row: get_vuln_idf(row['mess_bugs'], row[
                    'links'], row['cve'], row['mess_cves']),
                          axis=1))
            df['filepath_same_cnt'], df['filepath_same_ratio'], df[
                'filepath_unrelated_cnt'] = zip(
                    *df.apply(lambda row: get_vuln_loc(row['filepaths'], row[
                        'code_filepaths']),
                              axis=1))
            df['func_same_cnt'], df['func_same_ratio'], df[
                'func_unrelated_cnt'] = zip(*df.apply(lambda row: get_vuln_loc(
                    row['functions'], row['code_funcs']),
                                                      axis=1))
            df['file_same_cnt'], df['file_same_ratio'], df[
                'file_unrelated_cnt'] = zip(*df.apply(
                    lambda row: get_vuln_loc(row['files'], row['code_files']),
                    axis=1))
            df['vuln_type_1'], df['vuln_type_2'], df['vuln_type_3'] = zip(
                *df.apply(lambda row: get_vuln_type_relete(
                    row['vuln_type'], row['vuln_impact'], row['mess_type'],
                    row['mess_impact'], vuln_type_impact),
                          axis=1))
            df['mess_shared_num'], df['mess_shared_ratio'], df['mess_max'], df[
                'mess_sum'], df['mess_mean'], df['mess_var'] = zip(
                    *df.apply(lambda row: get_vuln_desc_text(
                        row['desc_token_counter'], row['mess_token_counter']),
                              axis=1))
            df['code_shared_num'], df['code_shared_ratio'], df['code_max'], df[
                'code_sum'], df['code_mean'], df['code_var'] = zip(
                    *df.apply(lambda row: get_vuln_desc_text(
                        row['desc_token_counter'], row['code_token_counter']),
                              axis=1))
            df.drop([
                'mess_bugs', 'links', 'mess_cves', 'functions', 'code_funcs',
                'filepaths', 'code_filepaths', 'files', 'code_files',
                'vuln_type', 'vuln_impact', 'mess_type', 'mess_impact',
                'desc_token_counter', 'mess_token_counter',
                'code_token_counter'
            ],
                    axis=1,
                    inplace=True)
            df.to_csv(dirpath + '/{:04}.csv'.format(i), index=False)

        t2 = time.time()
        logging.info('{}共耗时：{} min'.format(reponame, (t2 - t1) / 60))
        gc.collect()

        files = glob.glob(dirpath + '/*.csv')
        m = {}
        l = []
        for file in files:
            idx = int(re.search('([0-9]+).csv', file).group(1))
            m[idx] = file
        l = [pd.read_csv(m[i]) for i in range(epoch)]
        data_df2 = pd.concat(l)

        # 
        tmp_columns = [
            'cve_match', 'bug_match', 
            'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt', 
            'file_same_cnt', 'file_same_ratio', 'file_unrelated_cnt', 
            # vul_relevance, patch_likelihood,
            # 'filepath_same_cnt', 'filepath_same_ratio', 'filepath_unrelated_cnt', 
            'vuln_type_1', 'vuln_type_2', 'vuln_type_3', 
            'mess_shared_num', 'mess_shared_ratio', 'mess_max', 'mess_sum', 'mess_mean', 'mess_var', 
            'code_shared_num', 'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var'
        ]

        data_df = data_df2[tmp_columns]
        data_df.to_csv('../data/Dataset_5000_{}.csv'.format(reponame),
                       index=False)
