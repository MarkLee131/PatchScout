from utils import *
from encoding_module import *
import pandas as pd
import numpy as np
import time
from sklearn.model_selection import KFold
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
import torch.optim as optim

import warnings
warnings.filterwarnings('ignore')

class RankNet(nn.Module):
    def __init__(self, num_feature):
        super(RankNet, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(num_feature, 32),
            nn.Linear(32, 16), nn.Linear(16, 1))
        self.output_sig = nn.Sigmoid()
        # self.output_sig = nn.Sigmoid()
        # self.out = nn.Linear(16, 1)

    def forward(self, input_1, input_2):
        s1 = self.model(input_1)
        s2 = self.model(input_2)
        out = self.output_sig((s1 - s2))
        return out

    def predict(self, input_):
        s = self.model(input_)
        return s

def create_pair_data(df):
    label = []
    num_tcs = []
    array_0, array_1 = [], []
    idx = 0
    for cve, tmp_df in df.groupby(['cve']):
        true = tmp_df[tmp_df['label'] == 1]
        false = tmp_df[tmp_df['label'] == 0]
        true = true.drop(columns = ['cve', 'label'])
        false = false.drop(columns = ['cve', 'label'])
        for _, true_item in true.iterrows():
            idx += 1
            len_pair = len(false) if len(false) < 5000 else 5000
            num_tcs.append(len_pair)
            # if idx % 2 == 0:
            array_1.extend([np.array(true_item)] * len_pair)
            array_0.extend(np.array(false)[:len_pair])
            label.extend([1] * len_pair)
            # else:
            #     array_0.extend([np.array(true_item)] * len_pair)
            #     array_1.extend(np.array(false)[:len_pair])
            #     label.extend([0] * len_pair)
    return len(array_0), array_0, array_1, label, num_tcs

class PairDataset(Dataset):
    def __init__(self, df):
        self.datanum, self.array_0, self.array_1, self.label, self.num_tcs = create_pair_data(
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
    batch_size = 10000
    num_epoches = 10
    num_feature = X_train.shape[1]-2
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = RankNet(num_feature).to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)
    train_copy = X_train.copy()
    train_copy['label'] = y_train
    train_dataset = PairDataset(train_copy)
    test_copy = X_test.copy()
    test_copy['label'] = y_test
    test_dataset = PairDataset(test_copy)
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
            pred = [0 if item <= 0.5 else 1 for item in pred]
            label = label.cpu().detach().numpy()
        t2 = time.time()

        print('Epoch [{}/{}], Time {}s, Loss: {:.4f}, Lr:{:.4f}'.format(epoch + 1, num_epoches, int(t2 - t1), loss.item(), lr))
        torch.save(model.state_dict(),
                   '/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/model_data/ps_20_{:02}.ckpt'.format(epoch))

    model.eval()
    predict = []
    with torch.no_grad():
        num_tcs = test_dataset.num_tcs
        for i, (data1, data2, label) in enumerate(test_dataloader):
            data1 = data1.to(device)
            data2 = data2.to(device)
            pred = model(data1, data2)
            pred = pred.cpu().detach().numpy()
            pred = [0 if item <= 0.5 else 1 for item in pred]
            label = label.cpu().detach().numpy()
            x = np.bitwise_xor(pred, label)
            predict.extend(x)
    return predict, num_tcs

# sort data based on 'sortby' list, and then get the rank of each data
def get_rank(df, sortby, ascending=False):
    gb = df.groupby('cve')
    l = []
    for item1, item2 in gb:
        item2 = item2.reset_index()
        item2 = item2.sort_values(sortby + ['commit_id'], ascending=ascending)
        item2 = item2.reset_index(drop=True).reset_index()
        l.append(item2[['index', 'level_0']])

    df = pd.concat(l)
    df['rank'] = df['level_0']+1
    df = df.sort_values(['index'], ascending=True).reset_index(drop=True)
    return df['rank']

# get metric
def get_score_new(test, rankname='rank', N=10):
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

def get_full_score_new(df, suffix, result, start=1, end=10):
    metric1_list = []
    metric2_list = []
    for i in range(start, end+1):
        metric1, metric2 = get_score_new(df, 'rank_'+suffix, i)
        metric1_list.append(metric1)
        metric2_list.append(metric2)
    result['metric1_'+suffix] = metric1_list
    result['metric2_'+suffix] = metric2_list
    return result

def get_score2(predict, num_tcs:list, N=10):
    length = len(predict)
    total = sum(num_tcs)
    sum_arr = []
    if length != total:
        print('error: predict length is not equal to total')
    num_nozero = [ tc for tc in num_tcs if tc != 0]
    cnt_new = len(num_nozero)
    for i in range(cnt_new):
        arr = predict[sum(num_nozero[:i]): sum(num_nozero[:i+1])]
        sum_arr.append(sum(arr)+1)
        assert len(arr) == num_nozero[i]
    arr1 = [item if item <= N else N for item in sum_arr]
    arr2 = [1 if item <= N else 0 for item in sum_arr]
    return np.mean(arr1), sum(arr2) / cnt_new




def get_full_score2(predict, suffix, result, num_tcs, start=1, end=10):
    metric1_list = []
    metric2_list = []
    for i in range(start, end+1):
        metric1, metric2 = get_score2(predict, num_tcs, i)
        metric1_list.append(metric1)
        metric2_list.append(metric2)
    result['metric1_'+suffix] = metric1_list
    result['metric2_'+suffix] = metric2_list
    return result

if __name__ == '__main__':
    ps_df = pd.read_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/csv_data/patchscout_feature.csv")
    cvelist = ps_df.cve.unique()
    
    kf = KFold(n_splits = 2, shuffle = True)

    ps_cols = ['cve', 'label', 
                'cve_match', 'bug_match', # VI
                'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt', # VL
                'filepath_same_cnt', 'filepath_same_ratio', 'filepath_unrelated_cnt', # VL
                'file_same_cnt', 'file_same_ratio', 'file_unrelated_cnt',  # VL
                'patch_like', 'vuln_type_1', 'vuln_type_2', 'vuln_type_3', # VT
                'msg_shared_num', 'msg_shared_ratio', 'msg_max', 'msg_sum', 'msg_mean', 'msg_var', # VDT
                'code_shared_num', 'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var'] # VDT

    result_feature = ps_df[['cve', 'commit_id', 'label']]
    result_feature.loc[:, 'prob_ps'] = 0
    
    for idx, (train_index, test_index) in enumerate(kf.split(cvelist)):
        cve_train = cvelist[train_index]
        isTrain = ps_df.cve.apply(lambda item: item in cve_train)
        train = ps_df[isTrain]
        test = ps_df[isTrain == False]
        X_train = train[ps_cols]
        y_train = train['label']
        X_test = test[ps_cols]
        y_test = test['label']
        # patchscout
        patchScout_predict, num_tcs = patchScout(X_train, y_train, X_test, y_test)
        
        
        # save result
        # print("Length of X_test.index:", len(X_test.index))
        # print("Length of patchScout_predict:", len(patchScout_predict))
        # result_feature.loc[X_test.index, 'prob_ps'] = patchScout_predict
    # result_feature['rank_ps'] = get_rank(result_feature, ['prob_ps'])
    # result_feature.to_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/result_feature.csv", index=False)
    # save metric result
    
    result = pd.DataFrame()
    result = get_full_score2(patchScout_predict, 'ps', result, num_tcs)
    # result = get_full_score_new(result_feature, 'ps', result)
    result.to_csv("/home/kaixuan_cuda11/patch_match/analyze/PatchScout/data/metric_result.csv", index=False)
