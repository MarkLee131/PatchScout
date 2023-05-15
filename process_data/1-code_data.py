import warnings
import pandas as pd
import tqdm
from multiprocessing import Pool
import os


def get_code_info(cve, commit, diff):
    files, filepaths, funcs = [], [], []
    lines = diff.split('\n')
    for line in lines:
        if line.startswith('diff --git'):
            line = line.lower()
            files.append(line.split(' ')[-1].strip().split('/')[-1])
            filepaths.append(line.split(" ")[-1].strip())
        elif line.startswith('@@ '):
            line = line.lower()
            funcs.append(line.split('@@')[-1].strip())            
    return [cve, commit, files, filepaths, funcs]


def mid_func(item):
    return get_code_info(*item)


def multi_process_code(cves, commits, diffs, poolnum=5):
    length = len(commits)
    with Pool(poolnum) as p:
        # ret = list(
        #     tqdm.tqdm(p.imap(mid_func, zip(cves, commits, diffs )), total=length, desc='get commits info'))
        ret = list(p.imap(mid_func, zip(cves, commits, diffs )))
        p.close()
        p.join()
    return ret

##### several cves share commits

def get_code_info1(commit, diff):
    files, filepaths, funcs = [], [], []
    lines = diff.split('\n')
    for line in lines:
        if line.startswith('diff --git'):
            line = line.lower()
            files.append(line.split(' ')[-1].strip().split('/')[-1])
            filepaths.append(line.split(" ")[-1].strip())
        elif line.startswith('@@ '):
            line = line.lower()
            funcs.append(line.split('@@')[-1].strip())            
    return [commit, files, filepaths, funcs]


def mid_func1(item):
    return get_code_info1(*item)


def multi_process_code1(commits, diffs, poolnum=5):
    length = len(commits)
    with Pool(poolnum) as p:
        ret = list(
            tqdm.tqdm(p.imap(mid_func1, zip(commits, diffs )), total=length, desc='get commits info'))
        p.close()
        p.join()
    return ret




if __name__ == '__main__':
    ## on csl path 2023.03.30 total data
    df = pd.read_csv("/home/kaixuan/locating_patch/analyze/total_data/total_data.csv")
    # cve_id,owner,repo,commit_id

    nonpatch_diff_dir ='/home/kaixuan/cve/diff_info'
    patch_diff_dir = '/home/kaixuan/cve/total_patchdiff'
    code_savepath = '/home/kaixuan/locating_patch/analyze/PatchScout/data/code_data-1.csv'
    
    code_df = pd.DataFrame(columns=['cve','commit_id', 'code_files', 'code_filepaths', 'code_funcs', 'label'])
    code_df.to_csv(code_savepath, index=False, header=True)
    
    # need_add = ['2sic_2sxc',
    #     'ARM-software_CMSIS_5',
    #     'ARMmbed_mbed-os',
    #     'Exrick_xmall',
    #     'KDE_discover',
    #     'PKRoma_VeraCrypt',
    #     'ProCheckUp_SafeScan',
    #     'Yubico_yubico-piv-tool',
    #     'bnbdr_wd-rce'
    #     ]
    
    df = df.groupby(['owner', 'repo'])
    for name, group in tqdm.tqdm(df, total=len(df),desc='group by owner and repo'):
        owner = name[0]
        repo = name[1]
        # owner_repo = owner + '_' + repo
        # if owner_repo not in need_add:
        #     continue
            
        cves = group['cve_id'].tolist()       
        commit_ids = group['commit_id'].tolist()
        patch_diffs = []
        for commit_id in commit_ids:
            patch_diff_path = os.path.join(patch_diff_dir, owner + '_' + repo, commit_id+'.log')
            patch_diffs.append(open(patch_diff_path, 'r').read())
        patch_code_data = multi_process_code(cves, commit_ids, patch_diffs) #### commits is a list for commits
        patch_code_df = pd.DataFrame(patch_code_data, columns=['cve','commit_id', 'code_files', 'code_filepaths', 'code_funcs'])
        patch_code_df = pd.concat([patch_code_df, pd.DataFrame([1]*len(patch_code_data), columns=['label'])], axis=1)
        patch_code_df.to_csv(code_savepath, index=False, header=False, mode='a', encoding = 'utf-8', errors = 'replace')
        
        nonpatch_diffs = []
        nonpatch_commit_ids = []
        for file in os.listdir(os.path.join(nonpatch_diff_dir, owner + '_' + repo)):
            nonpatch_commit_id = file.split('.')[0]
            nonpatch_commit_ids.append(nonpatch_commit_id)
            nonpatch_diffs.append(open(os.path.join(nonpatch_diff_dir, owner + '_' + repo, file), 'r').read())
            
        non_code_data = multi_process_code1(nonpatch_commit_ids, nonpatch_diffs)
        tmp_nonpatch_code_df = pd.DataFrame(non_code_data, columns=['commit_id', 'code_files', 'code_filepaths', 'code_funcs'])
        
        tmp_df = pd.DataFrame(columns=['cve','commit_id', 'code_files', 'code_filepaths', 'code_funcs'])
        non_code_df = pd.DataFrame(columns=['cve','commit_id', 'code_files', 'code_filepaths', 'code_funcs', 'label'])
        for cve in cves:
            tmp_df = pd.concat([pd.DataFrame([cve]*len(non_code_data), columns=['cve']),  tmp_nonpatch_code_df, pd.DataFrame([0]*len(non_code_data), columns=['label'])], axis=1)
            non_code_df = pd.concat([non_code_df, tmp_df], axis=0)
        non_code_df.to_csv(code_savepath, index=False, header=False, mode='a', encoding = 'utf-8', errors = 'replace')
    