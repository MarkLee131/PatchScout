import logging
import pandas as pd
import json
import gc
from utils import *
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

# nltk.download('stopwords')
stop_words = set(stopwords.words('english'))

features_columns = ['cve_match', 'bug_match', # VI
                    'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt', # VL
                    'file_same_cnt', 'file_same_ratio', 'file_unrelated_cnt', # VL
                    'filepath_same_cnt', 'filepath_same_ratio', 'filepath_unrelated_cnt', # VL
                    'vuln_type_1', 'vuln_type_2', 'vuln_type_3', 'patch_like',  # VT
                    'msg_shared_num', 'msg_shared_ratio', 'msg_max', 'msg_sum', 'msg_mean', 'msg_var', # VDT
                    'code_shared_num', 'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var'] # VDT


def msg_sn(nvd_desc, commit_msg):
    # Tokenize the strings into words
    tokens1 = nltk.word_tokenize(nvd_desc.lower())
    tokens2 = nltk.word_tokenize(commit_msg.lower())
    # Remove stop words from the tokenized strings
    nvd_desc_tokens = [word for word in tokens1 if word not in stop_words]
    commit_msg_tokens = [word for word in tokens2 if word not in stop_words]
    # Get the shared words between the two tokenized strings
    shared_words = set(nvd_desc_tokens) & set(commit_msg_tokens)
    # Return a tuple containing the number of shared words and the computed statistics
    return len(shared_words)


if __name__ == '__main__':

    dataset_df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/drop_diffna.csv')
    dataset_df = reduce_mem_usage(dataset_df)
    vuln_df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/vuln_data-1.csv')
    msg_df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/msg_data.csv")
    
    msg_df['msg_bugs'] = msg_df['msg_bugs'].apply(eval)
    msg_df['msg_cves'] = msg_df['msg_cves'].apply(eval)
    msg_df['msg_type'] = msg_df['msg_type'].apply(eval)
    msg_df['msg_impact'] = msg_df['msg_impact'].apply(eval)
    
    
    tmp_df = ((dataset_df.merge(msg_df, how='left', on=['cve','commit_id']))).merge(vuln_df, how='left', on=['cve'])
    print(tmp_df.shape)
    # tmp_df = ((dataset_df.merge(code_df, how='left', on=['cve','commit_id'])).merge(msg_df, how='left', on=['cve','commit_id']))\
    #     .merge(vuln_df, how='left', on=['cve'])

    print(time.strftime("%H:%M:%S"))
    del dataset_df, vuln_df, msg_df
    # del dataset_df, code_df, msg_df
    gc.collect()
    print(time.strftime("%H:%M:%S"))
    
    total_cnt = tmp_df.shape[0]
    each_cnt = 2000
    epoch = int((total_cnt+each_cnt)/each_cnt)
    logging.info('共有{}个epoch'.format(epoch))
    print('共有{}个epoch'.format(epoch))
    
    tmp_savepath = '/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/msg_sn.csv'
    ps_df = pd.DataFrame(columns=['cve', 'commit_id', 'msg_shared_num' ])
    ps_df.to_csv(tmp_savepath, encoding='utf-8', mode='w', index=None)
    
    for i in tqdm.tqdm(range(epoch)):
        df = tmp_df.iloc[i * each_cnt: min((i + 1) * each_cnt, total_cnt)]
        ps_df = pd.DataFrame(columns=['cve', 'commit_id', 'msg_shared_num' ])
        ps_df['cve'] = df['cve']
        ps_df['commit_id'] = df['commit_id']
        ps_df['msg_shared_num'] = df.apply(lambda row: msg_sn(row['description'], row['commit_msg']), axis=1)
        ps_df.to_csv(tmp_savepath, index=False, mode='a', header=False)
