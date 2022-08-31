from keras.models import load_model
import pandas as pd
import numpy as np
import logging
import graypy
import time
from process_pcap import generate_features, prepare_samples, read_pcap_to_df, read_training_dataset, split_protocols

message_dict = {
    'ARP_spoofing': 'Attack detected: ARP Spoofing,',
    'Docker': 'Attack detected: Docker API compromise,',
    'Exploit': 'Attack detected: FTP server vulnerability exploit,', 
    'Hydra': 'Attack detected: SSH credentials bruteforcing,', 
    'Nmap_sV': 'Malicious activity detected: Running Nmap tool for ports scanning,', 
    'Regular_traffic': 'Network traffic looks as usually,', 
    'SQL_injection' : 'Attack detected: SQL injection,'
}

'''
    provide path to required pcap file and frequency 
'''
pcap_path = 'regular_traffic2_29_04.pcap'
frequency = '30S'
packets_df = read_pcap_to_df(pcap_path)
print(packets_df.head(10))
df_features = generate_features(packets_df, frequency)
df_features = split_protocols(df_features)

''' 
    we read the training set and merge it with new pcap to be able to properly normalize 
    the new data as otherwise normalized values are not comparable with what the model knows.
'''
training_df = read_training_dataset('features_merged_30_05_reduced_fixed_list.csv')
training_df_length = training_df.shape[0]
print(training_df_length)
merged_df = pd.concat([training_df, df_features], ignore_index=True, sort=False)
dataframe = prepare_samples(merged_df)
# remove training dataset after normalization 
dataframe = dataframe.iloc[training_df_length: , :]

my_logger = logging.getLogger('test_logger')
my_logger.setLevel(logging.DEBUG)

handler = graypy.GELFTCPHandler('localhost', 12201)
my_logger.addHandler(handler)

# multiclass model predictions
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

model = load_model('multiclass_classification_model.h5')
X = np.asarray(X).astype('float32')
y_pred = model.predict(X)
y_pred_rounded = np.round(y_pred, 2)
labels_list = ['ARP_spoofing', 'Docker', 'Exploit', 'Hydra', 'Nmap_sV', 'Regular_traffic', 'SQL_injection'] 
y_pred_df = pd.DataFrame(data=y_pred_rounded, columns = labels_list )

# second highest prediction value
y_second_pred = y_pred_df.apply(lambda row: row.nlargest(2).values[-1],axis=1)

# highest prediction value
y_max_pred= y_pred_df.max(axis=1)

# first and second predicted class
predictions_df = y_pred_df.apply(lambda s, n: pd.Series(s.nlargest(n).index), axis=1, n=2)
predictions_df = predictions_df.rename(columns = {0: "predicted_class_1", 1: "predicted_class_2"})
predictions_df['max_pred_val'] = y_max_pred
predictions_df['second_pred_val'] = y_second_pred

# binary model predictions
model_binary = load_model('binary_classification_model.h5')
binary_features_list = []
with open(r'features_binary_model.txt', 'r') as fp:
    for line in fp:
        x = line[:-1]
        binary_features_list.append(x)


X_binary = required_features_dataframe[binary_features_list]
y_pred_binary = model_binary.predict(X_binary)
predictions_df['binary_prediction'] = y_pred_binary
print(predictions_df)

for index, row in predictions_df.iterrows():
    
    # multiclass classification message
    message = message_dict[row['predicted_class_1']]
    message += ' model\'s confidence ' +  str(round(row['max_pred_val'] * 100, 2)) + '%.'
    if row['max_pred_val'] < 1.0:
        message += ' Predcition with the second highest value is: ' + row['predicted_class_2'] + ", with confidence: " + str(round(row['second_pred_val'] * 100, 2)) + '%.'
    my_logger.debug('Threat detection module: ' + message)
    print(message)

    # binary classification message 
    if row['binary_prediction'] < 0.48:
        message_binary_model = "network traffic looks as usually, model's confidence: " + str(round(row['binary_prediction'] * 100, 2)) + '%.'
    elif row['binary_prediction'] > 0.52:
        message_binary_model = "attack detected, model's confidence: " + str(round(row['binary_prediction'] * 100, 2)) + '%.'
    else: 
        message_binary_model = "equivocal prediction results."  
    my_logger.debug('Unknown threat detection module: ' + message_binary_model) 
    print('Unknown threat detection module: ' + message_binary_model)    
    time.sleep(1)
    
