import re
import warnings
import git
import json
import pandas as pd
from tqdm import tqdm
from utils import *
warnings.filterwarnings("ignore")


# =============== mess_data ===============


def re_bug(item):
    find = re.findall('bug.{0,3}([0-9]{2, 5})', item)
    return set(find)


def re_cve(item):
    return set(re.findall('(cve-[0-9]{4}-[0-9]{1,7})', item))


df = pd.read_csv(dataset_path)
df = reduce_mem_usage(df)

with open("../data/vuln_type_impact.json", 'r') as f:
    vuln_type_impact = json.load(f)

vuln_type = set(vuln_type_impact.keys())
vuln_impact = set()
for value in vuln_type_impact.values():
    vuln_impact.update(value)

commit_mess_data = []
repos = df.repo.unique()
for reponame in repos:
    repo = git.Repo(gitpath + '/' + reponame)
    df_tmp = df[df.repo == reponame]
    for commit in tqdm.tqdm(df_tmp.commit.unique()):
        mess = repo.commit(commit).message.lower()

        type_set = set()
        for value in vuln_type:
            if value in mess:
                type_set.add(value)

        impact_set = set()
        for value in vuln_impact:
            if value in mess:
                impact_set.add(value)

        bugs = re_bug(mess)
        cves = re_cve(mess)

        commit_mess_data.append([
            commit, bugs, cves, type_set, impact_set])

commit_mess_data = pd.DataFrame(commit_mess_data,
                                columns=[
                                    'commit', 'mess_bugs', 'mess_cves',
                                    'mess_type', 'mess_impact'
                                ])
commit_mess_data.to_csv("../data/mess_data.csv", index=False)