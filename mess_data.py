import re
import warnings
import git
import json
import pandas as pd
from tqdm import tqdm
from utils import *
warnings.filterwarnings("ignore")

def re_bug(item):
    find = re.findall('bug.{0,3}([0-9]{2, 5})', item)
    return set(find)


def re_cve(item):
    return set(re.findall('(cve-[0-9]{4}-[0-9]{1,7})', item))

if __name__ == "__main__":

    df = pd.read_csv(dataset_path)
    df = reduce_mem_usage(df)

    with open("../data/vuln_type_impact.json", 'r') as f:
        vuln_type_impact = json.load(f)

    vuln_type = set(vuln_type_impact.keys())
    vuln_impact = set()
    for value in vuln_type_impact.values():
        vuln_impact.update(value)

    commit_mess_data = []

    df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/drop_diffna.csv")
    df = reduce_mem_usage(df)
    msg_savepath = '/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/msg_data.csv'
    cves_name = df['cve'].tolist()
    commits = df['commit_id'].tolist()
    msgs = df['msg'].tolist()

    msg_len = len(msgs)

    for i in tqdm.tqdm(range(msg_len)):
        msg = msgs[i-1].lower()
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
        cve_name = cves_name[i-1]
        commit = commits[i-1]
        commit_mess_data.append([
            cve_name, commit, bugs, cves, type_set, impact_set])

    commit_mess_data = pd.DataFrame(commit_mess_data,
                                    columns=[
                                        'cve', 'commit', 'mess_bugs', 'mess_cves',
                                        'mess_type', 'mess_impact'
                                    ])
    commit_mess_data.to_csv(msg_savepath, index=False)
    
    ### TODO: test this script for the commit and msg, especially the 'msg' column name.