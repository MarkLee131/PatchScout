import nltk
import numpy as np
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import pandas as pd
from feature import get_diff_content, process_diff

# nltk.download('stopwords')
nltk.download('punkt')
stop_words = set(stopwords.words('english'))

### nvd_desc: nvd description
### commit_msg: commit message
def count_shared_words_dm(nvd_desc, commit_msg):
    # Tokenize the strings into words
    tokens1 = nltk.word_tokenize(nvd_desc.lower())
    tokens2 = nltk.word_tokenize(commit_msg.lower())

    # Remove stop words from the tokenized strings
    nvd_desc_tokens = [word for word in tokens1 if word not in stop_words]
    commit_msg_tokens = [word for word in tokens2 if word not in stop_words]

    # Get the shared words between the two filtered tokenized strings
    shared_words = set(nvd_desc_tokens) & set(commit_msg_tokens)
    # same with: shared_words = set(nvd_desc_tokens).intersection(set(commit_msg_tokens))
    
    # Compute the frequency of each shared word in both filtered tokenized strings
    freqs1 = [nvd_desc_tokens.count(word) for word in shared_words]
    freqs2 = [commit_msg_tokens.count(word) for word in shared_words]

    # Calculate the number of words in the first string
    num_words_nvd = len(nvd_desc_tokens)

    # Calculate the Shared-Vul-Msg-Word Ratio
    svmw_ratio = len(shared_words) / (num_words_nvd + 1)
    
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

def count_shared_words_dm_eq(nvd_desc, commit_msg):
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
    max_freq = max(list(nvd_desc_counts.values()) + list(commit_msg_counts.values()))

    # Calculate the sum of the frequencies of the shared words
    freq_sum = sum(list(nvd_desc_counts.values()) + list(commit_msg_counts.values()))

    # Calculate the average frequency of the shared words
    freq_avg = np.mean(list(nvd_desc_counts.values()) + list(commit_msg_counts.values()))

    # Calculate the variance of the frequency of the shared words
    freq_var = np.var(list(nvd_desc_counts.values()) + list(commit_msg_counts.values()))

    # Return a tuple containing the number of shared words and the computed statistics
    return len(shared_words), svmw_ratio, max_freq, freq_sum, freq_avg, freq_var


def count_shared_words_dc_eq(nvd_desc, code_diff):
    nvd_desc_tokens = word_tokenize(nvd_desc.lower())
    code_diff_tokens = []
    for line in code_diff.splitlines():
        if line.startswith('+'):
            code_diff_tokens += word_tokenize(line[1:].lower())
        elif line.startswith('-'):
            code_diff_tokens += word_tokenize(line[1:].lower())
    nvd_desc_tokens = [token for token in nvd_desc_tokens if token not in stop_words]
    code_diff_tokens = [token for token in code_diff_tokens if token not in stop_words]
    shared_words = set(nvd_desc_tokens) & set(code_diff_tokens)
    code_shared_num = len(shared_words)
    code_shared_ratio = code_shared_num / (len(nvd_desc_tokens) + 1)
    code_diff_counts = dict()
    for word in code_diff_tokens:
        if word in shared_words:
            code_diff_counts[word] = code_diff_counts.get(word, 0) + 1
    code_diff_values = list(code_diff_counts.values())
    if len(code_diff_values) == 0:
        code_diff_values = [0]
    code_max = max(code_diff_values)
    code_sum = sum(code_diff_values)
    code_mean = np.mean(code_diff_values)
    code_var = np.var(code_diff_values)
    return code_shared_num, code_shared_ratio, code_max, code_sum, code_mean, code_var

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





if __name__ == "__main__":
    ##############################################################################
    ps_df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/patchscout_feature_decra.csv')
    # msg_df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/msg_data.csv')
    msg_sn = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/msg_sn.csv')
    msg_df = msg_sn[['cve','msg_shared_num']]
    merged_df = ps_df.join(msg_df, how='left')
    merged_df.to_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/patchscout_feature_msg.csv', index=False)
    
    feature_df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/patchscout_feature_msg.csv')

    tmp_df = feature_df[['cve','commit_id','label','cve_match','bug_match','func_same_cnt','func_same_ratio','func_unrelated_cnt','file_same_cnt','file_same_ratio','file_unrelated_cnt','filepath_same_cnt','filepath_same_ratio','filepath_unrelated_cnt','vuln_type_1','vuln_type_2','vuln_type_3', 'patch_like','msg_shared_num','msg_shared_ratio','msg_max','msg_sum','msg_mean','msg_var','code_shared_num','code_shared_ratio','code_max','code_sum','code_mean','code_var']]
    # # reorder the columns
    # tmp_df = ps_df[['cve','commit_id','label','cve_match','bug_match','func_same_cnt','func_same_ratio','func_unrelated_cnt','file_same_cnt','file_same_ratio','file_unrelated_cnt','filepath_same_cnt','filepath_same_ratio','filepath_unrelated_cnt','vuln_type_1','vuln_type_2','vuln_type_3','msg_shared_num','msg_shared_ratio','msg_max','msg_sum','msg_mean','msg_var','code_shared_num','code_shared_ratio','code_max','code_sum','code_mean','patch_like']]

    # save the dataframe to a CSV file
    tmp_df.to_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/patchscout_feature.csv', index=False)

    
    
    # -----------------rename the column 'patchlike' as 'patch_like'-------------------------
    ps_df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/patchscout_feature.csv')
    new_name = 'patch_like'
    ps_df.rename(columns={ ps_df.columns[-1]: new_name }, inplace=True)
    # Delete the 'patchlike' column
    ps_df.drop(columns=['patchlike'], inplace=True)
    # Save the modified DataFrame to a new CSV file
    ps_df.to_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/patchscout_feature-1.csv', index=False) #,  header=[col if col != 'patch_like' else 'patch_like' for col in ps_df.columns])
    # ---------------------------------------------------------------------------------------
    
    nvd_description = "The vulnerable function uses user-controlled input to construct a file path for access without validating that the input is a valid file path."
    commit_message = "Fix file path validation in vulnerable function"
    shared_word_count, share_word_ratio, max_freq, freq_sum, freq_avg, freq_var = count_shared_words_dm(nvd_description, commit_message)
    print(f"Number of shared words: {shared_word_count}")
    print(f"Ratio of shared words: {share_word_ratio}")
    print(f"Max frequency of shared words: {max_freq}")
    print(f"Sum of frequencies of shared words: {freq_sum}")
    print(f"Average frequency of shared words: {freq_avg}")
    print(f"Variance of frequency of shared words: {freq_var}")

    print("*"*59)
    shared_word_count, share_word_ratio, max_freq, freq_sum, freq_avg, freq_var = count_shared_words_dm_eq(nvd_description, commit_message)
    print(f"Number of shared words: {shared_word_count}")
    print(f"Ratio of shared words: {share_word_ratio}")
    print(f"Max frequency of shared words: {max_freq}")
    print(f"Sum of frequencies of shared words: {freq_sum}")
    print(f"Average frequency of shared words: {freq_avg}")
    print(f"Variance of frequency of shared words: {freq_var}")


    print("*"*59)
    code_diff = "+This is a line of added code\n-This is a line of deleted code\n+This is another line of added code for fix vulnerability\n"
    nvd_desc = "This is a description of a vulnerability"
    code_shared_num, code_shared_ratio, code_max, code_sum, code_mean, code_var = count_shared_words_dc(nvd_desc, code_diff)
    print(f"Code shared num: {code_shared_num}")
    print(f"Code shared ratio: {code_shared_ratio}")
    print(f"Code max: {code_max}")
    print(f"Code sum: {code_sum}")
    print(f"Code mean: {code_mean}")
    print(f"Code var: {code_var}")



    print("*"*59)
    code_diff = "+This is a line of added code\n-This is a line of deleted code\n+This is another line of added code for fix vulnerability\n"
    nvd_desc = "This is a description of a vulnerability"
    code_shared_num, code_shared_ratio, code_max, code_sum, code_mean, code_var = count_shared_words_dc_eq(nvd_desc, code_diff)
    print(f"Code shared num: {code_shared_num}")
    print(f"Code shared ratio: {code_shared_ratio}")
    print(f"Code max: {code_max}")
    print(f"Code sum: {code_sum}")
    print(f"Code mean: {code_mean}")
    print(f"Code var: {code_var}")


    print("*"*59)
    code_diff = "+This is a line of added code\n-This is a line of deleted code\n+This is another line of added code for fix vulnerability\n"
    nvd_desc = "This is a description of a vulnerability"
    code_shared_num, code_shared_ratio, code_max, code_sum, code_mean, code_var = count_shared_words_counter_eq(nvd_desc, code_diff)
    print(f"Code shared num: {code_shared_num}")
    print(f"Code shared ratio: {code_shared_ratio}")
    print(f"Code max: {code_max}")
    print(f"Code sum: {code_sum}")
    print(f"Code mean: {code_mean}")
    print(f"Code var: {code_var}")


    df = pd.read_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/patchscout_feature.csv')
    cnt = 0
    cve_list = []
    for cve, tmp_df in df.groupby(['cve']):
        true = tmp_df[tmp_df['label'] == 1]
        false = tmp_df[tmp_df['label'] == 0]
        # true = true.drop(columns = ['cve', 'label'])
        # false = false.drop(columns = ['cve', 'label'])
        len_pair = len(false) if len(false) < 5000 else 5000
        if len_pair == 0:
                cnt += 1
                cve_list.append(cve)
    
    print(len(cve_list))
    print(len(set(cve_list))) 
    print(cve_list)         
    print(cnt)
    tmp_df = pd.DataFrame(cve_list, columns=['cve'])
    tmp_df.to_csv('/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/cve_list_todo.csv', index=False)
    #### dprecated ##################################################################################################
    
    cve = 'CVE-2015-5232'
    commit_id = 'c5759e7b76f5bf844be6c6641cc1b356bbc83869'
    commit_id_1 = '931e02b6e05042fa051d077ae15ae13ad808857a'
    label_1 = 0
    label = 1
    code_diff = get_diff_content(cve, commit_id, label)
    print(code_diff)
    print('-'*59)
    nvd_desc = "This is a description of a vulnerability, int sm_skip_attr_write"
    code_shared_num, code_shared_ratio, code_max, code_sum, code_mean, code_var = count_shared_words_dc(nvd_desc, code_diff)
    print(f"Code shared num: {code_shared_num}, Code shared ratio: {code_shared_ratio}, Code max: {code_max}, Code sum: {code_sum}, Code mean: {code_mean}, Code var: {code_var}")
