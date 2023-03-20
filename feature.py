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

    # Calculate l1
    if nvd_type and commit_type:
        for nvd_item in nvd_type:
            if nvd_item in commit_type:
                l1 += 1
    # l1 = len(nvd_type & commit_type)

    # Calculate l2 and l3
    if nvd_type and commit_impact:
        for nvd_item in nvd_type:
            impact_list = vuln_type_impact.get(nvd_item)
            if impact_list is None:
                l3 += 1
                continue
            for commit_item in commit_impact:
                if commit_item in impact_list:
                    l2 += 1
                else:
                    l3 += 1

    if commit_type and nvd_impact:
        for commit_item in commit_type:
            impact_list = vuln_type_impact.get(commit_item)
            if impact_list is None:
                l3 += 1
                continue
            for nvd_item in nvd_impact:
                if nvd_item in impact_list:
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

### nvd_desc: nvd description
### commit_msg: commit message
def count_shared_words_dm(nvd_desc, commit_msg):
    # Tokenize the strings into words
    tokens1 = nltk.word_tokenize(nvd_desc.lower())
    tokens2 = nltk.word_tokenize(commit_msg.lower())

    # Remove stop words from the tokenized strings
    nvd_desc_tokens = [word for word in tokens1 if word not in stop_words]
    commit_msg_tokens = [word for word in tokens2 if word not in stop_words]

    # Get the shared words between the two tokenized strings
    shared_words = set(nvd_desc_tokens) & set(commit_msg_tokens)

    # Compute the frequency of each shared word in both tokenized strings
    nvd_desc_counts = {}
    commit_msg_counts = {}
    for word in shared_words:
        nvd_desc_counts[word] = nvd_desc_tokens.count(word)
        commit_msg_counts[word] = commit_msg_tokens.count(word)

    # Calculate the number of words in nvd description
    num_words_nvd = len(nvd_desc_tokens)

    # Calculate the Shared-Vul-Msg-Word Ratio
    svmw_ratio = len(shared_words) / (num_words_nvd + 1)

    # Calculate the maximum frequency of the shared words
    max_freq = max(list(nvd_desc_counts.values()) + list(commit_msg_counts.values()), default=0)
    
    # Calculate the sum of the frequencies of the shared words
    freq_sum = sum(list(nvd_desc_counts.values())) + sum(list(commit_msg_counts.values())) if len(shared_words) > 0 else 0

    # Calculate the average frequency of the shared words
    freq_avg = np.mean(list(nvd_desc_counts.values()) + list(commit_msg_counts.values())) if len(shared_words) > 0 else 0

    # Calculate the variance of the frequency of the shared words
    freq_var = np.var(list(nvd_desc_counts.values()) + list(commit_msg_counts.values())) if len(shared_words) > 0 else 0

    # Return a tuple containing the number of shared words and the computed statistics
    return len(shared_words), svmw_ratio, max_freq, freq_sum, freq_avg, freq_var

def process_diff(diff):
    code_diff_tokens = []
    for line in diff.splitlines():
        if (line.startswith('+') and not line.startswith('++')) or (
                line.startswith('-') and not line.startswith('--')):
            line = line.lower()
            tmp_list = []
            tmp_list = word_tokenize(line[1:])
            code_diff_tokens.extend([token for token in tmp_list if token not in stop_words])
    return code_diff_tokens

def count_shared_words_dc(nvd_desc, code_diff):
    nvd_desc_tokens = word_tokenize(nvd_desc.lower())
    nvd_desc_tokens = [token for token in nvd_desc_tokens if token not in stop_words]
    
    code_diff_tokens = process_diff(code_diff)
    # code_diff_tokens = [token for token in code_diff_tokens if token not in stop_words]
    
    shared_words = set(nvd_desc_tokens) & set(code_diff_tokens)

    # Compute the frequency of each shared word in both tokenized strings
    nvd_desc_counts = {}
    code_diff_counts = {}
    for word in shared_words:
        nvd_desc_counts[word] = nvd_desc_tokens.count(word)
        code_diff_counts[word] = code_diff_tokens.count(word)

    # Calculate the number of words in nvd description
    num_words_nvd_desc = len(nvd_desc_tokens)
    
    # Calculate the Shared-Vul-Msg-Word Ratio
    svmw_ratio = len(shared_words) / (num_words_nvd_desc + 1)

    # Calculate the maximum frequency of the shared words
    max_freq = max(list(nvd_desc_counts.values()) + list(code_diff_counts.values()), default=0)


    # Calculate the sum of the frequencies of the shared words
    freq_sum = sum(list(nvd_desc_counts.values())) + sum(list(code_diff_counts.values())) if len(shared_words) > 0 else 0

    # Calculate the average frequency of the shared words
    freq_avg = freq_sum / (len(nvd_desc_counts) + len(code_diff_counts) + 1)

    # Calculate the variance of the frequency of the shared words
    freq_var = np.var(list(nvd_desc_counts.values()) + list(code_diff_counts.values())) if len(shared_words) > 0 else 0
    # Return the computed statistics
    return len(shared_words), svmw_ratio, max_freq, freq_sum, freq_avg, freq_var




if __name__ == '__main__':
    # cve,commit_id,commit_msg,diff,label
    dataset_df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/drop_diffna.csv')
    dataset_df = reduce_mem_usage(dataset_df)
    vuln_df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/vuln_data-1.csv')
    # vuln_df['description'] = vuln_df['description'].apply(eval)
    
    code_df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/code_data.csv")
    msg_df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/msg_data.csv")
    
    code_df['code_files'] = code_df['code_files'] .apply(eval)
    code_df['code_funcs'] = code_df['code_funcs'].apply(eval)
    code_df['code_filepaths'] = code_df['code_filepaths'] .apply(eval)
    msg_df['msg_bugs'] = msg_df['msg_bugs'].apply(eval)
    msg_df['msg_cves'] = msg_df['msg_cves'].apply(eval)
    msg_df['msg_type'] = msg_df['msg_type'].apply(eval)
    msg_df['msg_impact'] = msg_df['msg_impact'].apply(eval)
    
    tmp_df = ((dataset_df.merge(code_df, how='left', on=['cve','commit_id'])).merge(msg_df, how='left', on=['cve','commit_id']))\
        .merge(vuln_df, how='left', on=['cve'])
    # df: cve,commit_id,commit_msg,diff,label
    # code_df: cve,commit_id,code_files,code_filepaths,code_funcs
    # vuln_df: cve,description,functions,files,filepaths,vuln_type,vuln_impact,links
    # msg_df: cve,commit_id,msg_bugs,msg_cves,msg_type,msg_impact
    # tmp_df: cve,commit_id,commit_msg,diff,label,code_files,code_filepaths,code_funcs,msg_bugs,msg_cves,msg_type,msg_impact
    print(time.strftime("%H:%M:%S"))
    del dataset_df, code_df, msg_df
    gc.collect()
    print(time.strftime("%H:%M:%S"))
    
    total_cnt = tmp_df.shape[0]
    each_cnt = 2000
    epoch = int((total_cnt+each_cnt)/each_cnt)
    logging.info('共有{}个epoch'.format(epoch))

    vuln_type_impact = json.load(open('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/vuln_type_impact.json'))

    ps_savepath = '/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/patchscout_feature.csv'
    col_names = ['cve','commit_id','label'] + features_columns
    print(col_names)
    ps_df=pd.DataFrame(columns=col_names)
    ps_df.to_csv(ps_savepath, encoding='utf-8', mode='w', index=None)

    for i in tqdm.tqdm(range(epoch)):
        df = tmp_df.iloc[i * each_cnt: min((i + 1) * each_cnt, total_cnt)]

        # tmp_df: cve,commit_id,commit_msg,diff,label,code_files,code_filepaths,code_funcs,msg_bugs,msg_cves,msg_type,msg_impact
        ps_df = pd.DataFrame(columns=col_names)
        ps_df['cve'] = df['cve']
        ps_df['commit_id'] = df['commit_id']
        ps_df['label'] = df['label']
        #### VI
        ps_df['cve_match'], ps_df['bug_match'] = zip(*df.apply(
            lambda row: get_vuln_idf(row['msg_bugs'], row['links'], row['cve'], row['msg_cves']), axis=1))
        
        #### VL
        ps_df['func_same_cnt'], ps_df['func_same_ratio'], ps_df['func_unrelated_cnt'] = zip(*df.apply(
            lambda row: get_vuln_loc(row['functions'], row['code_funcs']), axis=1))

        ## but file &&&& filepaths ??
        ps_df['file_same_cnt'], ps_df['file_same_ratio'], ps_df['file_unrelated_cnt'] = zip(*df.apply(
            lambda row: get_vuln_loc(row['files'], row['code_files']), axis=1))
        ps_df['filepath_same_cnt'], ps_df['filepath_same_ratio'], ps_df['filepath_unrelated_cnt'] = zip(*df.apply(
            lambda row: get_vuln_loc(row['filepaths'], row['code_filepaths']), axis=1))

        #### VT 
        ps_df['vuln_type_1'], ps_df['vuln_type_2'], ps_df['vuln_type_3'] = zip(*df.apply(
            lambda row: get_vuln_type_relevance(row['vuln_type'], row['vuln_impact'], row['msg_type'], row['msg_impact'], vuln_type_impact), axis=1))
        ps_df['patch_like'] = 0.5
        # vuln_type, vuln_impact: set()
        # msg_bugs, msg_cves, msg_type, msg_impact: set()
        
        #### VDT 
        ps_df['msg_shared_num'], ps_df['msg_shared_ratio'], ps_df['msg_max'], ps_df['msg_sum'], ps_df['msg_mean'], ps_df['msg_var'] = zip(*df.apply(
            lambda row: count_shared_words_dm(row['description'], row['commit_msg']), axis=1))
        ps_df['code_shared_num'], ps_df['code_shared_ratio'], ps_df['code_max'], ps_df['code_sum'], ps_df['code_mean'], ps_df['code_var'] = zip(*df.apply(
            lambda row: count_shared_words_dc(row['description'], row['diff']), axis=1))
        
        # cve,commit_id,commit_msg,diff,label,code_files,code_filepaths,code_funcs,msg_bugs,msg_cves,msg_type,msg_impact

        # df.drop(['diff', 'code_files', 'code_filepaths', 'code_funcs', 'msg_bugs', 'msg_cves', 'msg_type', 'msg_impact', 'description','functions', 'files', 'filepaths', 'vuln_type', 'vuln_impact', 'links'], axis=1, inplace=True)
        
        ps_df.to_csv(ps_savepath, index=False, mode='a', header=False)
        # break
    
    # ps_df = pd.read_csv(ps_savepath)
    # ps_df = reduce_mem_usage(ps_df)
    # ps_df['patchlike'] = 0.5
    # ps_df.to_csv(ps_savepath, index=False)