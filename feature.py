import logging
import os
import pandas as pd
from collections import Counter
import json
from utils import *
# import nltk

features_columns = ['cve_match', 'bug_match', # VI
                    'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt', # VL
                    'file_same_cnt', 'file_same_ratio', 'file_unrelated_cnt', # VL
                    'vuln_type_1', 'vuln_type_2', 'vuln_type_3', 'patchlike',  # VT
                    'msg_shared_num', 'msg_shared_ratio', 'msg_max', 'msg_sum', 'msg_mean', 'msg_var', # VDT
                    'code_shared_num', 'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var'] # VDT



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


### string1: nvd description
### string2: commit message
def count_shared_words(string1, string2):
    # Tokenize the strings into words
    tokens1 = nltk.word_tokenize(string1.lower())
    tokens2 = nltk.word_tokenize(string2.lower())

    # Get the shared words between the two tokenized strings
    shared_words = set(tokens1).intersection(set(tokens2))

    # Compute the frequency of each shared word in both tokenized strings
    freqs1 = [tokens1.count(word) for word in shared_words]
    freqs2 = [tokens2.count(word) for word in shared_words]

    # Calculate the number of words in the NVD description
    num_words_nvd = len(tokens1)

    # Calculate the Shared-Vul-Msg-Word Ratio
    svmw_ratio = len(shared_words) / num_words_nvd
    
    # Calculate the maximum frequency of the shared words
    max_freq = max(freqs1 + freqs2)

    # Calculate the sum of the frequencies of the shared words
    freq_sum = sum(freqs1 + freqs2)

    # Calculate the average frequency of the shared words
    freq_avg = np.mean(freqs1 + freqs2)

    # Calculate the variance of the frequency of the shared words
    freq_var = np.var(freqs1 + freqs2)

    # Return a tuple containing the number of shared words and the computed statistics
    return len(shared_words), svmw_ratio, max_freq, freq_sum, freq_avg, freq_var

# # c1 # nvd
# # c2 # code
# def get_VDT(c1, c2):
#     c3 = c1 and c2
#     same_token = c3.keys()
#     shared_num = len(same_token)
#     shared_ratio = shared_num / (len(c1.keys()) + 1)
#     c3_value = list(c3.values())
#     if len(c3_value) == 0:
#         c3_value = [0]
#     return shared_num, shared_ratio, max(c3_value), sum(c3_value), np.mean(
#         c3_value), np.var(c3_value)




if __name__ == '__main__':
    # cve,commit_id,commit_msg,diff,label
    df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/drop_diffna.csv')
    df = reduce_mem_usage(df)
    vuln_df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/vuln_data-1.csv')
    # vuln_df['description'] = vuln_df['description'].apply(eval)
    
    code_df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/code_data.csv")
    code_df = reduce_mem_usage(code_df)
    
    msg_df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/msg_data.csv")
    msg_df = reduce_mem_usage(msg_df)
    
    code_df['code_files'] = code_df['code_files'] .apply(eval)
    code_df['code_funcs'] = code_df['code_funcs'].apply(eval)
    code_df['code_filepaths'] = code_df['code_filepaths'] .apply(eval)

    tmp_df = ((df.merge(code_df, how='left', on=['cve','commit_id'])).merge(msg_df, how='left', on=['cve','commit_id']))\
        .merge(vuln_df, how='left', on=['cve'])
    # df: cve,commit_id,commit_msg,diff,label
    # code_df: cve,commit_id,code_files,code_filepaths,code_funcs
    # vuln_df: cve,description,functions,files,filepaths,vuln_type,vuln_impact,links
    # msg_df: cve,commit_id,msg_bugs,msg_cves,msg_type,msg_impact
    # tmp_df: cve,commit_id,commit_msg,diff,label,code_files,code_filepaths,code_funcs,msg_bugs,msg_cves,msg_type,msg_impact
    print(time.strftime("%H:%M:%S"))
    total_cnt = tmp_df.shape[0]
    each_cnt = 2000
    epoch = int((total_cnt+each_cnt)/each_cnt)
    logging.info('共有{}个epoch'.format(epoch))

    vuln_type_impact = json.load(open('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/vuln_type_impact.json'))

    ps_savepath = '/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/patchscout_feature.csv'
    
    ### TODO: need to set the headers for ps features
    # df.to_csv(ps_savepath, index=False, columns=['cve','commit_id','commit_msg','diff','label'])
    
    for i in tqdm.tqdm(range(epoch)):
        # if os.path.exists(dirpath+'/{:04}.csv'.format(i)):
        #     continue
        df = tmp_df.iloc[i * each_cnt: min((i + 1) * each_cnt, total_cnt)]

# tmp_df: cve,commit_id,commit_msg,diff,label,code_files,code_filepaths,code_funcs,msg_bugs,msg_cves,msg_type,msg_impact


        #### VI
        df['cve_match'], df['bug_match'] = zip(*df.apply(
            lambda row: get_vuln_idf(row['msg_bugs'], row['links'], row['cve'], row['msg_cves']), axis=1))
        
        #### VL
        df['func_same_cnt'], df['func_same_ratio'], df['func_unrelated_cnt'] = zip(*df.apply(
            lambda row: get_vuln_loc(row['functions'], row['code_funcs']), axis=1))

        ## but file &&&& filepaths ??
        df['file_same_cnt'], df['file_same_ratio'], df['file_unrelated_cnt'] = zip(*df.apply(
            lambda row: get_vuln_loc(row['files'], row['code_files']), axis=1))
        df['filepath_same_cnt'], df['filepath_same_ratio'], df['filepath_unrelated_cnt'] = zip(*df.apply(
            lambda row: get_vuln_loc(row['filepaths'], row['code_filepaths']), axis=1))

        #### VT, need to add patchlike: 0.5
        df['vuln_type_1'], df['vuln_type_2'], df['vuln_type_3'] = zip(*df.apply(
            lambda row: get_vuln_type_relevance(row['vuln_type'], row['vuln_impact'], row['msg_type'], row['msg_impact'], vuln_type_impact), axis=1))
        
        #### VDT TODO: what is code_token_counter??? 
        #### code token maybe need to be preprocessed, we should collect the code added.
        df['msg_shared_num'], df['msg_shared_ratio'], df['msg_max'], df['msg_sum'], df['msg_mean'], df['msg_var'] = zip(*df.apply(
            lambda row: count_shared_words(row['description'], row['commit_msg']), axis=1))
        df['code_shared_num'], df['code_shared_ratio'], df['code_max'], df['code_sum'], df['code_mean'], df['code_var'] = zip(*df.apply(
            lambda row: count_shared_words(row['description'], row['code_token_counter']), axis=1))
        
        
        df.to_csv(ps_savepath, index=False, mode='a', header=False)
    