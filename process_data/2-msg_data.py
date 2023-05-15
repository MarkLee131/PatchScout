import re
import warnings
import git
import json
import pandas as pd
from tqdm import tqdm
from multiprocessing import Pool
# from PatchScout.utils import *
warnings.filterwarnings("ignore")

with open("/home/kaixuan/locating_patch/analyze/PatchScout/data/vuln_type_impact.json", 'r') as f:
    vuln_type_impact = json.load(f)

vuln_type = set(vuln_type_impact.keys())
vuln_impact = set()
for value in vuln_type_impact.values():
    vuln_impact.update(value)


def re_bug(item):
    find = re.findall('bug.{0,3}([0-9]{2, 5})', item)
    return set(find)


def re_cve(item):
    return set(re.findall('(cve-[0-9]{4}-[0-9]{1,7})', item))


def process_msg1(msg, commit_id):
    type_set = set()
    for value in vuln_type:
        if value in msg:
            type_set.add(value)

    impact_set = set()
    for value in vuln_impact:
        if value in msg:
            impact_set.add(value)

    bugs = re_bug(msg)
    cves = re_cve(msg)
    return [commit_id, bugs, cves, type_set, impact_set]



def mid_func1(item):
    return process_msg1(*item)


def multi_process_msg1(commit_msgs, commit_ids, poolnum=5):
    length = len(commit_ids)
    with Pool(poolnum) as p:
        ret = list(
            p.imap(mid_func1, zip(commit_msgs, commit_ids)))
        p.close()
        p.join()
    return ret

#-----------------------------

def process_msg(cve_name, msg, commit_id):
    type_set = set()
    for value in vuln_type:
        if value in msg:
            type_set.add(value)

    impact_set = set()
    for value in vuln_impact:
        if value in msg:
            impact_set.add(value)
    bugs = re_bug(msg)
    cves = re_cve(msg)
    return [cve_name, commit_id, bugs, cves, type_set, impact_set]

def mid_func(item):
    return process_msg(*item)

def multi_process_msg(cves, commit_msgs, commit_ids, poolnum=5):
    length = len(commit_ids)
    with Pool(poolnum) as p:
        ret = list(
            p.imap(mid_func, zip(cves, commit_msgs, commit_ids )))
        p.close()
        p.join()
    return ret
#-----------------------------


if __name__ == "__main__":
    commit_msg_data = []
    
    df = pd.read_csv("/home/kaixuan/locating_patch/analyze/total_data/total_data.csv")
    msg_savepath = '/home/kaixuan/locating_patch/analyze/PatchScout/data/msg_data.csv'

    ## --------------read patch and nonpatch msg df
    patch_msg_df = pd.read_csv("/home/kaixuan/locating_patch/analyze/total_data/total_msg.csv").fillna('')
    # cve_id,owner,repo,commit_id,commit_msg
    nonpatch_msg_df = pd.read_csv("/home/kaixuan/locating_patch/analyze/total_data/total_non_msg.csv").fillna('')
    # owner,repo,commit_id,commit_msg,label
    ## --------------

    total_df = df.groupby(['owner','repo'])
    
    msg_df = pd.DataFrame(columns=['cve','commit_id','msg_bugs','msg_cves','msg_type','msg_impact','label'])
    msg_df.to_csv(msg_savepath, index=False, header=True)
    
    for name, group in tqdm(total_df, total=len(total_df), desc='group by owner and repo'):
        owner = name[0]
        repo = name[1]
        cves = group['cve_id'].tolist()
        
        ## load patch and nonpatch msg df
        tmp_patch_df = patch_msg_df[(patch_msg_df['owner'] == owner) & (patch_msg_df['repo'] == repo)]
        tmp_nonpatch_df = nonpatch_msg_df[(nonpatch_msg_df['owner'] == owner) & (nonpatch_msg_df['repo'] == repo)]
        
        ## get patch commit msg list
        patch_msgs = tmp_patch_df['commit_msg'].tolist()
        patch_commit_ids = tmp_patch_df['commit_id'].tolist()
        ## get nonpatch commit msg list
        nonpatch_msgs = tmp_nonpatch_df['commit_msg'].tolist()
        nonpatch_commit_msgs = [str(nonpatch_msg) for nonpatch_msg in nonpatch_msgs]
        
        nonpatch_commit_ids = tmp_nonpatch_df['commit_id'].tolist()

        ## get patch commit msg and save
        patch_commit_msgs = multi_process_msg(cves, patch_msgs, patch_commit_ids)
        patch_df = pd.DataFrame(patch_commit_msgs, columns=['cve', 'commit_id', 'msg_bugs', 'msg_cves', 'msg_type', 'msg_impact'])
        patch_df = pd.concat([patch_df, pd.DataFrame([1]*len(patch_commit_msgs), columns=['label'])], axis=1)
        patch_df.to_csv(msg_savepath, index=False, mode='a', header=False)
        
        ## get nonpatch commit msg and save
        nonpatch_commit_msgs = multi_process_msg1(nonpatch_msgs, nonpatch_commit_ids)
        nonpatch_msgs_df = pd.DataFrame(nonpatch_commit_msgs, columns=['commit_id', 'msg_bugs', 'msg_cves', 'msg_type', 'msg_impact'])

        tmp_df = pd.DataFrame(patch_commit_msgs, columns=['cve', 'commit_id', 'msg_bugs', 'msg_cves', 'msg_type', 'msg_impact'])
        nonpatch_df = pd.DataFrame(columns=['cve','commit_id','msg_bugs','msg_cves','msg_type','msg_impact','label'])
        for cve in cves:
            tmp_df = pd.concat([pd.DataFrame([cve]*len(nonpatch_commit_msgs), columns=['cve']),  nonpatch_msgs_df, pd.DataFrame([0]*len(nonpatch_commit_msgs), columns=['label'])], axis=1)
            nonpatch_df = pd.concat([nonpatch_df, tmp_df], axis=0)
        nonpatch_df.to_csv(msg_savepath, index=False, mode='a', header=False)

