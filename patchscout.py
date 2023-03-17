from ctypes import POINTER
import math
import sys
from analyze.PatchScout.utils import *
from encoding_module import *
import pandas as pd
import numpy as np
import time
import logging
import xgboost as xgb
import lightgbm as lgb
from sklearn.linear_model import LinearRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import KFold
from sklearn.metrics import mean_squared_log_error

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
import torch.optim as optim
from torch.autograd import Variable

import warnings
warnings.filterwarnings('ignore')
num_epochs=20

class RankNet(nn.Module):
    def __init__(self, num_feature):
        super(RankNet, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(num_feature, 32),
            nn.Linear(32, 16),
            nn.Linear(16, 1))
        self.output_sig = nn.Sigmoid()

    def forward(self, input_1, input_2):
        s1 = self.model(input_1)
        s2 = self.model(input_2)
        out = self.output_sig(s1 - s2)
        return out

    def predict(self, input_):
        s = self.model(input_)
        return s


# def create_pair_data(df):
#     label = []
#     array_0, array_1 = [], []
#     idx = 0
#     for cve, tmp_df in df.groupby(['cve']):
#         true = tmp_df[tmp_df['label'] == 1]
#         false = tmp_df[tmp_df['label'] == 0]
#         for true_item in true.iterrows():
#             idx += 1
#             if idx % 2 == 0:
#                 array_1.extend(
#                     [np.array(true_item[1].drop(['label'], axis=1))] * 5000)
#                 array_0.extend(np.array(false.drop(['label'], axis=1)))
#                 label.extend([1]*5000)
#             else:
#                 array_0.extend(
#                     [np.array(true_item[1].drop(['label'], axis=1))] * 5000)
#                 array_1.extend(np.array(false.drop(['label'], axis=1)))
#                 label.extend([0]*5000)
#     return len(array_0), array_0, array_1, label

def create_pair_data(df):
    label = []
    array_0, array_1 = [], []
    idx = 0
    for cve, tmp_df in df.groupby(['cve']):
        true = tmp_df[tmp_df['label'] == 1]
        false = tmp_df[tmp_df['label'] == 0]
        for true_item in true.iterrows():
            idx += 1
            if idx % 2 == 0:
                array_1.extend(
                    [np.array(true_item[1].drop(['label'], axis=1))] * 5000)
                array_0.extend(np.array(false.drop(['label'], axis=1)))
                label.extend([1]*5000)
            else:
                array_0.extend(
                    [np.array(true_item[1].drop(['label'], axis=1))] * 5000)
                array_1.extend(np.array(false.drop(['label'], axis=1)))
                label.extend([0]*5000)
    return len(array_0), array_0, array_1, label


class PairDataset(Dataset):
    def __init__(self, df):
        self.datanum, self.array_0, self.array_1, self.label = create_pair_data(
            df)

    def __len__(self):
        return self.datanum

    def __getitem__(self, idx):
        data1 = torch.from_numpy(self.array_0[idx]).float()
        data2 = torch.from_numpy(self.array_1[idx]).float()
        label = torch.tensor(self.label[idx])
        return data1, data2, label


def patchScout(X_train, y_train, X_test, y_test):
    lr = 0.001
    num_workers = 10
    alpha = 10
    batch_size = 10000
    num_epoches = 20
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)
    train_copy = X_train.copy()
    train_copy['label'] = y_train
    train_dataset = PairDataset(train_copy)
    test_copy = X_test.copy()
    test_copy['label'] = y_test
    test_dataset = PairDataset(test_copy)

    num_feature = X_train.shape[1]
    model = RankNet(num_feature).to(device)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    train_dataloader = DataLoader(dataset=train_dataset,
                                  batch_size=batch_size,
                                  shuffle=False,
                                  num_workers=num_workers,
                                  pin_memory=False)
    test_dataloader = DataLoader(dataset=test_dataset,
                                 batch_size=batch_size,
                                 shuffle=False,
                                 num_workers=num_workers,
                                 pin_memory=False)

    print("ps training & predicting")
    for epoch in range(num_epoches):
        model.train()
        t1 = time.time()

        for i, (data1, data2, label) in enumerate(train_dataloader):
            data1 = data1.to(device)
            data2 = data2.to(device)
            label = label.to(device)
            pred = model(data1, data2)
            label_size = data1.size()[0]
            loss = criterion(pred, label.unsqueeze(1).float())
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            pred = pred.cpu().detach().numpy()
            pred = [0 if item[0] <= 0.5 else 1 for item in pred]
            label = label.cpu().detach().numpy()
            x = np.bitwise_xor(pred, label)
            res.extend(x)
        res = np.numpy(res)
        t2 = time.time()
        logging.Logger.info('Epoch [{}/{}], Time {}s, Loss: {:.4f}, Lr:{:.4f}'.format(
            epoch + 1, num_epochs, int(t2 - t1), loss.item(), lr))
        torch.save(model.state_dict(),
                   '../data/ps_20_{:02}.ckpt'.format(epoch))

    model.eval()
    predict = []
    with torch.no_grad():
        for i, (data1, data2, label) in enumerate(test_dataloader):
            data1 = data1.to(device)
            data2 = data2.to(device)
            pred = model(data1, data2)
            pred = pred.cpu().detach().numpy()
            pred = [0 if item[0] <= 0.5 else 1 for item in pred]
            label = label.cpu().detach().numpy()
            x = np.bitwise_xor(pred, label)
            predict.extend(x)
    return predict


# ======================== metric ========================
N = 10


# sort data based on 'sortby' list, and then get the rank of each data
def get_rank(df, sortby, ascending=False):
    gb = df.groupby('cve')
    l = []
    for item1, item2 in gb:
        item2 = item2.reset_index()
        item2 = item2.sort_values(sortby + ['commit'], ascending=ascending)
        item2 = item2.reset_index(drop=True).reset_index()
        l.append(item2[['index', 'level_0']])

    df = pd.concat(l)
    df['rank'] = df['level_0']+1
    df = df.sort_values(['index'], ascending=True).reset_index(drop=True)
    return df['rank']


# get metric
def get_score(test, rankname='rank', N=10):
    cve_list = []
    cnt = 0
    total = []
    gb = test.groupby('cve')
    for item1, item2 in gb:
        item2 = item2.sort_values(
            [rankname], ascending=True).reset_index(drop=True)
        idx = item2[item2.label == 1].index[0]+1
        if idx <= N:
            total.append(idx)
            cnt += 1
        else:
            total.append(N)
            cve_list.append(item1)
    return np.mean(total), cnt / len(total)


def get_score2(predict):
    length = len(predict)
    cnt = length//5000
    sum_arr = []
    for i in range(cnt):
        arr = predict[i*5000: (i+1)*5000]
        sum_arr.append(sum(arr)+1)
    arr1 = [item if item <= N else N for item in sum_arr]
    arr2 = [1 if item <= N else 0 for item in sum_arr]
    return np.mean(arr1), sum(arr2) / cnt

# get metrix on top 1-10


def get_full_score(df, suffix, result, start=1, end=10):
    metric1_list = []
    metric2_list = []
    for i in range(start, end+1):
        metric1, metric2 = get_score(df, 'rank_'+suffix, i)
        metric1_list.append(metric1)
        metric2_list.append(metric2)
    result['metric1_'+suffix] = metric1_list
    result['metric2_'+suffix] = metric2_list
    return result


def get_full_score2(predict, suffix, result, start=1, end=10):
    metric1_list = []
    metric2_list = []
    for i in range(start, end+1):
        metric1, metric2 = get_score2(predict)
        metric1_list.append(metric1)
        metric2_list.append(metric2)
    result['metric1_'+suffix] = metric1_list
    result['metric2_'+suffix] = metric2_list
    return result


# ======================== 5-fold cross-validation ========================

df = pd.read_csv("../data/Dataset_5000.csv")
cvelist = df.cve.unique()

kf = KFold(n_splits=5, shuffle=True)

ps_cols = ['cve_match', 'bug_match', 'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt',
           'filepath_same_cnt', 'filepath_same_ratio', 'filepath_unrelated_cnt',
           'file_same_cnt', 'file_same_ratio', 'file_unrelated_cnt', 'patchlike', 'vuln_type_1',
           'vuln_type_2', 'vuln_type_3', 'mess_shared_num', 'mess_shared_ratio',
           'mess_max', 'mess_sum', 'mess_mean', 'mess_var', 'code_shared_num',
           'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var']


# print(df.shape[1])
result = df[['cve', 'commit', 'label']]
result.loc[:, 'prob_linear'] = 0
result.loc[:, 'prob_logistic'] = 0
result.loc[:, 'prob_xgb'] = 0
result.loc[:, 'prob_lgb'] = 0
result.loc[:, 'prob_cnn'] = 0

for idx, (train_index, test_index) in enumerate(kf.split(cvelist)):
    cve_train = cvelist[train_index]
    isTrain = df.cve.apply(lambda item: item in cve_train)
    train = df[isTrain]
    test = df[isTrain == False]
    tmp_train = train[['cve', 'repo', 'commit']].copy()
    tmp_test = test[['cve', 'repo', 'commit']].copy()
    note = 'idx_'+str(idx) # fix: revert the type of idx: int to str
    # encoding(tmp_train, tmp_test, note)
    outpath = '../data/encode/'
    
    feature_df = pd.read_csv('../data/Dataset_feature.csv')
    ps_df = pd.read_csv('../data/Dataset_5000_FFmpeg.csv')
    ps_df['patchlike'] = 0.5
    print("ps_col:",ps_df.shape[1])
    print(len(ps_cols))
    train = train.merge(feature_df, on=['cve', 'repo', 'commit'], how='left')
    print(train.columns)

    for col in ps_cols:
        if col not in ps_df.columns:
            print(col)


    # X_train = train[feature_cols + vuln_cols + cmt_cols]
    X_train = train
    y_train = train['label']
    # X_test = test[feature_cols + vuln_cols + cmt_cols]
    X_test = test
    y_test = test['label']


    # patchscout
    patchScout_predict = patchScout(X_train[ps_cols], y_train, X_test[ps_cols], y_test)




# save metric result
result2 = pd.DataFrame()
result2 = get_full_score2(patchScout_predict, 'ps', result2)
result2.to_csv("../data/metric_result.csv", index=False)
