from keras.models import load_model
import pandas as pd
import numpy as np
from data_prep import prepare_samples
import logging
import time

dataframe = pd.read_csv('features_merged_unknown_23_08.csv')
dataframe = prepare_samples(dataframe, for_training=False)
print(dataframe.columns)
y = dataframe['class2']

# read the features list for multiclassification model 
merged_features_list = []
with open(r'features_multiclass_model.txt', 'r') as fp:
    for line in fp:
        x = line[:-1]
        merged_features_list.append(x)

required_features_dataframe = pd.DataFrame(columns=merged_features_list)
required_features_dataframe = pd.concat([required_features_dataframe,dataframe])
required_features_dataframe = required_features_dataframe.fillna(0) 
X = required_features_dataframe[merged_features_list]
X = X.drop(columns = 'class2')
print(X)
print(y)

model = load_model('multiclass_classification_model.h5')
X = np.asarray(X).astype('float32')
y_pred = model.predict(X)
y_pred_rounded = np.round(y_pred, 2)
labels_list = ['ARP_spoofing', 'Docker', 'Exploit', 'Hydra', 'Nmap_sV', 'Regular_traffic', 'SQL_injection'] 
y_pred_df = pd.DataFrame(data=y_pred_rounded, columns = labels_list )
y_pred_df = pd.DataFrame(data=y_pred_rounded, columns = labels_list )
print(y_pred_df)
# second highest prediction value 
print(y_pred_df.to_string())
y_second_pred = y_pred_df.apply(lambda row: row.nlargest(2).values[-1],axis=1)
print(y_second_pred)

# highest prediction value
y_max_pred= y_pred_df.max(axis=1)
print(y_max_pred.to_string())

# first and second predicted class
predictions_df = y_pred_df.apply(lambda s, n: pd.Series(s.nlargest(n).index), axis=1, n=2)
predictions_df = predictions_df.rename(columns = {0: "predicted_class_1", 1: "predicted_class_2"})
predictions_df['max_pred_val'] = y_max_pred
predictions_df['second_pred_val'] = y_second_pred
print(predictions_df)


# test with binary model
model_binary = load_model('binary_classification_model.h5')
binary_features_list = []
with open(r'features_binary_model.txt', 'r') as fp:
    for line in fp:
        x = line[:-1]
        binary_features_list.append(x)


X_binary = required_features_dataframe[binary_features_list]
print(X_binary)
y_pred_binary = model_binary.predict(X_binary)
print(y_pred_binary)