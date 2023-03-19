import nltk
import numpy as np

### string1: nvd description
### string2: commit message/ code diff
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



if __name__ == "__main__":

    nvd_description = "The vulnerable function uses user-controlled input to a a"
    commit_message = "Fix a a a a file path validation in the vulnerable function"
    
    nvd_description = "The vulnerable function uses user-controlled input to construct a file path for access without validating that the input is a valid file path."
    commit_message = "Fix file path validation in vulnerable function"
    shared_word_count, share_word_ratio, max_freq, freq_sum, freq_avg, freq_var = count_shared_words(nvd_description, commit_message)
    print(f"Number of shared words: {shared_word_count}")
    print(f"Ratio of shared words: {share_word_ratio}")
    print(f"Max frequency of shared words: {max_freq}")
    print(f"Sum of frequencies of shared words: {freq_sum}")
    print(f"Average frequency of shared words: {freq_avg}")
    print(f"Variance of frequency of shared words: {freq_var}")








    # # Convert strings to sets of words
    # nvd_words = set(nvd_description.lower().split())
    # commit_words = set(commit_message.lower().split())

    # # Calculate the intersection of the sets
    # shared_words = nvd_words.intersection(commit_words)

    # # Print the number of shared words
    # print(f"Number of shared words: {len(shared_words)}")
