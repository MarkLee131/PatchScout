import re
import os
import warnings
import git
import pandas as pd
from tqdm import tqdm
from multiprocessing import Pool
from nltk.corpus import stopwords
from utils import *
warnings.filterwarnings("ignore")


def get_info(repo, commit):
    outputs = repo.git.diff(commit + '~1',
                            commit,
                            ignore_blank_lines=True,
                            ignore_space_at_eol=True).split('\n')

    temp_commit = repo.commit(commit)
    # data to be collected
    weblinks, bug, issue, cve = [], [], [], []
    filepaths, funcs = [], []
    addcnt, delcnt = 0, 0
    # get commit message
    mess = temp_commit.message
    # get weblink bugID issueID cveID
    link_re = r'https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]'
    weblinks.extend(re.findall(link_re, mess))
    bug.extend(re.findall('[bB]ug[^0-9]{0,5}([0-9]{1,7})[^0-9]', mess))
    issue.extend(re.findall('[iI]ssue[^0-9]{0,5}([0-9]{1,7})[^0-9]', mess))
    cve.extend(re.findall('[CVEcve]{3}-[0-9]+-[0-9]+', mess))
    # get commit time
    datetime = pd.Timestamp(temp_commit.committed_date, unit='s')
    datetime = '{:04}{:02}{:02}'.format(datetime.year, datetime.month,
                                        datetime.day)

    for line in outputs:
        # get weblink bugID issueID cveID in code diff
        weblinks.extend(re.findall(link_re, line))
        bug.extend(re.findall('[bB]ug[^0-9]{0,5}([0-9]{1,7})[^0-9]', line))
        issue.extend(re.findall('[iI]ssue[^0-9]{0,5}([0-9]{1,7})[^0-9]', line))
        cve.extend(re.findall('[CVEcve]{3}-[0-9]+-[0-9]+', line))
        # get filepaths and funcnames in code diff
        # get added and deleted lines of code
        if line.startswith('diff --git'):
            filepath = line.split(' ')[-1].strip()[2:]
            filepaths.append(filepath)
        elif line.startswith('@@ '):
            funcname = line.split('@@')[-1].strip()
            funcname = funcs_preprocess(funcname)
            funcs.append(funcname)
        else:
            if line.startswith('+') and not line.startswith('++'):
                addcnt = addcnt + 1
            elif line.startswith(
                    '-') and not line.startswith('--'):
                delcnt = delcnt + 1

    return set(weblinks), set(bug), set(issue), set(cve), datetime, set(
        filepaths), set(funcs), addcnt, delcnt


def get_commit_info(data):
    out = get_info(data[0], data[1])
    return (data[1], out)


def multi_process_get_commit_info(repo, commits):
    length = len(commits)
    with Pool(5) as p:
        ret = list(
            tqdm.tqdm(p.imap(get_commit_info, zip(*([repo] * length, commits))),
                 total=length,
                 desc='get commits info'))
        p.close()
        p.join()
    return ret

if __name__ == '__main__':

    df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/drop_diffna.csv")
    df = reduce_mem_usage(df)
    msg_savepath = '/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/msg_data.csv'
    cves_name = df['cve'].tolist()
    commits = df['commit_id'].tolist()
    msgs = df['msg'].tolist()

    ###### stop here.
    
    dataset_df = pd.read_csv('../data/Dataset_5000.csv')
    repos = dataset_df.repo.unique()
    dataset_df = reduce_mem_usage(dataset_df)
    path = '../data/commit_info'
    if not os.path.exists(path):
        os.makedirs(path)
    for reponame in repos:
        repo = git.Repo('../gitrepo/{}'.format(reponame))
        commits = dataset_df[dataset_df.repo == reponame].commit.unique()
        result = multi_process_get_commit_info(repo, commits)
        savefile(dict(result), path + '/' + reponame + '_commit_info')
