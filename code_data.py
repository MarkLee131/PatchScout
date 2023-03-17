import warnings
import pandas as pd
from tqdm import tqdm
from multiprocessing import Pool
from utils import *
warnings.filterwarnings("ignore")

# =============== code_data =============== 

### process code data, to obtain the code information of each commit.
### 'commit', 'code_files', 'code_filepaths', 'code_funcs'

# ### TODO: need to change the logic of this part: we already have the diff.
# def get_code_info(repo, commit):
#     outputs = repo.git.diff(commit + '~1',
#                             commit,
#                             ignore_blank_lines=True,
#                             ignore_space_at_eol=True).split('\n')
#     files, filepaths, funcs = [], [], []
#     for line in outputs:
#         if line.startswith('diff --git'):
#             line = line.lower()
#             files.append(line.split(' ')[-1].strip().split('/')[-1])
#             filepaths.append(line.split(" ")[-1].strip())
#         elif line.startswith('@@ '):
#             line = line.lower()
#             funcs.append(line.split('@@')[-1].strip())            
#     return [commit, files, filepaths, funcs]

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
        ret = list(
            tqdm.tqdm(p.imap(mid_func, zip(cves, commits, diffs )), total=length, desc='get commits info'))
        p.close()
        p.join()
    return ret


if __name__ == '__main__':
    ### Created by Kaixuan 
    ### read diff of each commit from the csv file (20G), and return their code information.
    
    df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/drop_diffna.csv")
    df = reduce_mem_usage(df)
    # cve_df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/cve_info.csv")
    # cve_df = reduce_mem_usage(cve_df)
    
    # repos = cve_df.repo.unique()

    # code_data_path = '/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/code_data'
    # if not os.path.exists(code_data_path):
    #     os.makedirs(code_data_path)

    # for reponame in repos:
    #     savepath = code_data_path+'/code_data_' + reponame + '.csv'
    #     if os.path.exists(savepath):
    #         continue

        # print(reponame+" is processing...")
        
        # commits = df[df.repo == reponame].commit.unique()
    savepath = '/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/code_data.csv'
    cves = df['cve'].tolist()
    commits = df['commit_id'].tolist()
    diffs = df['diff'].tolist()
    code_data = multi_process_code(cves, commits, diffs) #### commits is a list for commits
    code_df = pd.DataFrame(
        code_data,
        columns=['cve','commit_id', 'code_files', 'code_filepaths', 'code_funcs'])
    code_df.to_csv(savepath, index=False)
