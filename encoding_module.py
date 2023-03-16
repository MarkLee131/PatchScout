import seaborn as sns
import pandas as pd
import numpy as np
import pickle
import os
import gc
import time
import logging
import git
import chardet

from util import *
import random
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from torch.nn.utils.rnn import pad_sequence
from transformers import BertTokenizer, BertModel, AutoModel
from transformers import logging as lg
lg.set_verbosity_error()


class TextDataset(Dataset):
    def __init__(self, df):
        self.labels = torch.tensor(df['label'])
        # self.input1 = list(df['desc_token'].apply(torch.tensor))
        self.input1 = list(df['desc_id'].apply(torch.tensor))
        self.input1 = pad_sequence(self.input1).T.to(torch.int64)
        # self.input2 = list(df['mess_token'].apply(torch.tensor))
        self.input2 = list(df['mess_id'].apply(torch.tensor))
        self.input2 = pad_sequence(self.input2).T.to(torch.int64)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        label = self.labels[idx]
        input1 = self.input1[idx]
        input2 = self.input2[idx]
        sample = (input1, input2, label)
        return sample


class TextModel(nn.Module):
    def __init__(self):
        super(TextModel, self).__init__()
        self.bert = AutoModel.from_pretrained("../data/bert_model_path")
        self.linear = nn.Linear(768, 256)
        self.linear2 = nn.Linear(256, 32)
        self.linear3 = nn.Linear(64, 2)

    def forward(self, input1, input2):
        out1 = self.linear2(self.linear(self.bert(input1)[1]))
        out2 = self.linear2(self.linear(self.bert(input2)[1]))
        out = torch.cat((out1, out2), 1)
        out = self.linear3(out)
        return out


def add_desc(df, filepath='../data/cve_desc.csv'):
    # kaixuan: add encoding to avoid error
    desc = pd.read_csv(filepath,encoding='Windows-1252')
    df = df.merge(desc, on='cve', how='left')
    return df


def add_mess(df, gitdir='../gitrepo/'):
    def get_commit_message(reponame, commit):
        gitrepo = git.Repo(gitdir + reponame)
        mess = ''
        try:# Some commits may be deleted, so we need to catch the exception
            temp_commit = gitrepo.commit(commit)  # 获取commit对象
            mess = temp_commit.message  # 获取commit的备注信息
        except Exception as e:
            print(e, commit)
            pass
        return mess

    df['mess'] = df.apply(
        lambda row: get_commit_message(row['repo'], row['commit']), axis=1)
    return df


def dataProcess(df, tokenizer, columns=['mess', 'desc']):
    for col in columns:
        df[col + '_token'] = df[col].apply(tokenizer.tokenize)
        df[col + '_id'] = df[col + '_token'].apply(
            tokenizer.convert_tokens_to_ids)
        df[col + '_id'] = df[col + '_id'].apply(lambda x: x[:128])
        df.drop([col], axis=1, inplace=True)
    return df


###Note: label is added.
### output: 'cve', 'repo', 'commit', 'mess_token', 'mess_id', 'desc_token', 'desc_id', 'label'
def prepare_encoding():
    if not os.path.exists('../data/encode/TextEmbedding.csv'):
        df = pd.read_csv('../data/Dataset_5000.csv')
        df = df[['cve', 'repo', 'commit','label']]
        df = add_desc(df)
        df = add_mess(df)
        tokenizer = BertTokenizer.from_pretrained('../data/bert_model_path')
        df = dataProcess(df, tokenizer)
        df.to_csv('../data/encode/TextEmbedding.csv', index=False)


def create_encode_dataset_k_split(train_cve):
    prepare_encoding()
    df = pd.read_csv('../data/encode/TextEmbedding.csv')
    # tokenizer = BertTokenizer.from_pretrained('data/bert_model_path')
    # df = dataProcess(df, tokenizer)
    inTrain = df.cve.apply(lambda item: True if item in train_cve else False)
    inTest = df.cve.apply(lambda item: True
                          if item not in train_cve else False)
    train_df = df[inTrain]
    test_df = df[inTest]
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)
    train_df['desc_id'] = train_df['desc_id'].apply(lambda x: x[:128])
    test_df['desc_id'] = test_df['desc_id'].apply(lambda x: x[:128])
    train_df['mess_id'] = train_df['mess_id'].apply(lambda x: x[:128])
    test_df['mess_id'] = test_df['mess_id'].apply(lambda x: x[:128])
    trainDataset = TextDataset(train_df)
    testDataset = TextDataset(test_df)
    savefile(trainDataset, '../data/encode/temp_enc_train')
    savefile(testDataset, '../data/encode/temp_enc_test')
    return


def create_encode_dataset_repo(test_repo):
    prepare_encoding()
    df = pd.read_csv('../data/encode/TextEmbedding.csv')
    # tokenizer = BertTokenizer.from_pretrained('data/bert_model_path')
    # df = dataProcess(df, tokenizer)
    inTrain = df.repo.apply(lambda item: True
                            if item not in test_repo else False)
    inTest = df.repo.apply(lambda item: True if item in test_repo else False)
    train_df = df[inTrain]
    test_df = df[inTest]
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)
    train_df['desc_id'] = train_df['desc_id'].apply(lambda x: x[:128])
    test_df['desc_id'] = test_df['desc_id'].apply(lambda x: x[:128])
    train_df['mess_id'] = train_df['mess_id'].apply(lambda x: x[:128])
    test_df['mess_id'] = test_df['mess_id'].apply(lambda x: x[:128])
    trainDataset = TextDataset(train_df)
    testDataset = TextDataset(test_df)
    savefile(trainDataset, '../data/encode/temp_enc_train')
    savefile(testDataset, '../data/encode/temp_enc_test')


def create_encode_dataset(train_df,
                          test_df,
                          trainDatasetPath='/home/kaixuan/locating_patch/analyze/VCMatch/data/encode/temp_enc_train',
                          testDatasetPath='../data/encode/temp_enc_test'):
    prepare_encoding()
    df = pd.read_csv('../data/encode/TextEmbedding.csv')
    # train_df = pd.merge(left=train_df,
    #                     right=df,
    #                     left_on=['cve', 'repo', 'commit'],right_on=['mess_token', 'mess_id', 'desc_token', 'desc_id'])
    train_df = pd.merge(left=train_df, right=df, on=['cve', 'repo', 'commit'])
    # test_df = pd.merge(left=test_df,
    #                    right=df,
    #                    left_on=['cve', 'repo', 'commit'], right_on=['mess_token', 'mess_id', 'desc_token', 'desc_id'])
    test_df = pd.merge(left=test_df, right=df, on=['cve', 'repo', 'commit'])

    train_df['desc_id'] = train_df['desc_id'].apply(lambda x: eval(x)[:128])
    test_df['desc_id'] = test_df['desc_id'].apply(lambda x: eval(x)[:128])
    train_df['mess_id'] = train_df['mess_id'].apply(lambda x: eval(x)[:128])
    test_df['mess_id'] = test_df['mess_id'].apply(lambda x: eval(x)[:128])

    trainDataset = TextDataset(train_df)
    testDataset = TextDataset(test_df)
    savefile(trainDataset, trainDatasetPath)
    savefile(testDataset, testDatasetPath)


def train_enc(trainDatasetPath,
              testDatasetPath,
              criterion=None,
              optimizer=None,
              num_epochs=5,# 20 default
              batch_size=20,
              shuffle=False,
              num_workers=4,
              learning_rate=2e-5):
    trainDataset = readfile(trainDatasetPath)
    testDataset = readfile(testDatasetPath)
    trainDataLoader = DataLoader(trainDataset,
                                 batch_size=batch_size,
                                 shuffle=shuffle,
                                 num_workers=num_workers)
    testDataLoader = DataLoader(testDataset, batch_size=batch_size,  shuffle=shuffle, num_workers=num_workers)
    

    model = TextModel().to(device)
    if criterion is None:
        criterion = nn.CrossEntropyLoss()
    if optimizer is None:
        optimizer = optim.Adam(model.parameters(), lr=learning_rate)

    for epoch in range(num_epochs):
        t1 = time.time()
        model.train()
        loss_sum = 0
        for i, (data1, data2, label) in enumerate(trainDataLoader):
            data1 = data1.to(device)
            data2 = data2.to(device)
            label = label.to(device)
            label_size = data1.size()[0]
            pred = model(data1, data2)
            loss = criterion(pred, label)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            loss_sum = loss_sum + loss.item()
        t2 = time.time()
        logging.info('Epoch [{:2}/{:2}], Loss: {:.4f}, Time: {:4}s'.format(
            epoch + 1, num_epochs, loss.item(), int(t2 - t1)))
        evaluation(model, trainDataLoader)
        evaluation(model, testDataLoader)
        logging.info("")
        torch.save(
            model.state_dict(),
            '../data/encode/model_epoch_{}_{}.ckpt'.format(num_epochs, epoch))


def evaluation(model, dataloader):
    model.eval()
    TP, FP, FN, TN, cnt = 0, 0, 0, 0, 0
    with torch.no_grad():
        for i, (data1, data2, label) in enumerate(dataloader):
            data1 = data1.to(device)
            data2 = data2.to(device)
            label = label.to(device)
            label_size = data1.size()[0]
            pred = model(data1, data2)
            pred_label = pred.argmax(axis=1)
            for item1, item2 in zip(pred_label, label):
                item1 = int(item1)
                item2 = int(item2)
                if item1 == item2 and item1 == 1:
                    TP += 1
                elif item1 == item2:
                    TN += 1
                elif item2 == 1:
                    FP += 1
                else:
                    FN += 1
            cnt += label_size

    TN = cnt - TP - FP - FN
    if (TP + FP) == 0:
        precision = 0
    else:
        precision = TP / (TP + FP)
    if (TP + FN) == 0:
        recall = 0
    else:
        recall = TP / (TP + FN)
    if cnt == 0:
        accuracy = 0
    else:
        accuracy = (TP + TN) / cnt
    logging.info("precision:{:.4f}, recall: {:.4f}, accuracy: {:.4f}".format(
        precision, recall, accuracy))
    logging.info("TP = {:4d}, FP = {:4d}, FN = {:4d}, TN = {:4d}".format(
        TP, FP, FN, TN))


def get_embedding(model,
                  dataset_path,
                  batch_size=20,
                  shuffle=False,
                  num_workers=4,
                  note='data', 
                  outpath = '../data/encode/'):
    dataset = readfile(dataset_path)
    dataloader = DataLoader(dataset,
                            batch_size=batch_size,
                            shuffle=shuffle,
                            num_workers=num_workers)

    model.eval()
    data1_embedding = []
    data2_embedding = []
    result = []
    with torch.no_grad():
        for i, (data1, data2, label) in enumerate(dataloader):
            data1 = data1.to(device)
            data2 = data2.to(device)
            out1 = model.linear2(model.linear(model.bert(data1)[1]))
            out2 = model.linear2(model.linear(model.bert(data2)[1]))
            out = torch.cat((out1, out2), 1)
            out = model.linear3(out)
            data1_embedding.extend(out1.cpu().numpy())
            data2_embedding.extend(out2.cpu().numpy())
    data1_embedding = np.array(data1_embedding)
    data2_embedding = np.array(data2_embedding)
    savefile(data1_embedding, outpath + 'vuln_embedding_' + note)
    savefile(data2_embedding, outpath + 'commit_embedding_' + note)


# def encoding():
#     df = pd.read_csv('data/Dataset_5000.csv')
#     if not os.path.exists('data/encode/cve_desc_token.csv'):
#         cve_desc = pd.read_csv('data/cve_desc.csv',encoding= 'Windows-1252')
#         cve_unique = df.cve.unique()
#         in_use = cve_desc['cve'].apply(lambda x: True if x in cve_unique else False)
#         cve_desc_origin_use = cve_desc[in_use]
#         cve_desc_origin_use['desc_token'] = cve_desc_origin_use['desc'].apply(lambda x: tokenizer.convert_tokens_to_ids(tokenizer.tokenize(x))[:128])
#         cve_desc_origin_use.drop('desc', axis = 1, inplace = True)
#         cve_desc_origin_use.to_csv('data/encode/cve_desc_token.csv', index=False)

#     cve_desc_origin_use = pd.read_csv('data/encode/cve_desc_token.csv')
#     cve_desc_origin_use['desc_token'] = cve_desc_origin_use['desc_token'].apply(eval)

#     if not os.path.exists('data/encode/commit_mess_token.csv'):
#         repo_commit = df.drop_duplicates(['repo', 'commit'])
#         repo_commit = repo_commit[['repo', 'commit']]
#         repo_commit.to_csv('data/encode/repo_commit.csv', index=False)
#         for repo in repo_unique:
#             dic = {}
#             gitRepo = git.Repo('gitrepo/'+repo)
#             for commit in gitRepo.iter_commits():
#                 dic[str(commit)] = commit.message
#             repo_tmp = repo_commit[repo_commit.repo == repo]
#             repo_tmp['mess_token'] = repo_tmp['commit'].apply(lambda x: tokenizer.convert_tokens_to_ids(tokenizer.tokenize(dic[x]))[:128])
#             repo_tmp.to_csv('data/encode/repo_commit_'+repo+'.csv', index=False)
#         repo_commit_list = []
#         for repo in repo_unique:
#             tmp = pd.read_csv('data/encode/repo_commit_{}.csv'.format(repo))
#             repo_commit_list.append(tmp)
#             os.remove('data/encode/repo_commit_{}.csv'.format(repo))
#         repo_commit = pd.concat(repo_commit_list)
#         repo_commit.to_csv('data/encode/commit_mess_token.csv', index=False)

#     repo_commit = pd.read_csv('data/encode/repo_commit_mess_token.csv')
#     repo_commit['mess_token'] = repo_commit['mess_token'].apply(eval)

#     df = df.merge(cve_desc_origin_use, how='left', on='cve').merge(repo_commit, how='left', on=['repo', 'commit'])


def encoding(train_df, test_df, note):
    trainDatasetPath = '../data/encode/enc_train_' + note
    testDatasetPath = '../data/encode/enc_test_' + note
    print("生成数据集")
    logging.info("生成数据集")
    create_encode_dataset(train_df, test_df, trainDatasetPath, testDatasetPath)
    print("训练encoding module")
    logging.info("训练encoding module")
    # train_enc(trainDatasetPath=trainDatasetPath,testDatasetPath=testDatasetPath)
    print("对文本进行编码")
    logging.info("对文本进行编码")
    model = TextModel().to(device)
    model.load_state_dict(torch.load('../data/encode/model_epoch_5_4.ckpt'))
    get_embedding(model, trainDatasetPath, note='train')
    get_embedding(model, testDatasetPath, note='test')
