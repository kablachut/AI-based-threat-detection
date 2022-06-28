from keras.models import load_model
import pandas as pd
import numpy as np
from data_prep import prepare_samples
import logging
import graypy
import time

message_dict = {
    'ARP_spoofing': 'Attack detected: ARP Spoofing.',
    'Docker': 'Attack detected: Docker API compromise.',
    'Exploit': 'Attack detected: FTP server vulnerability exploit.', 
    'Hydra': 'Attack detected: SSH credentials bruteforcing.', 
    'Nmap_sV': 'Malicious activity detected: Running Nmap tool for ports scanning.', 
    'Regular_traffic': 'Network traffic looks as usually.', 
    'SQL_injection' : 'Attack detected: SQL injection.'
}

my_logger = logging.getLogger('test_logger')
my_logger.setLevel(logging.DEBUG)

handler = graypy.GELFTCPHandler('localhost', 12201)
my_logger.addHandler(handler)

merged_features_list = []
with open(r'merged_features.txt', 'r') as fp:
    for line in fp:
        x = line[:-1]
        merged_features_list.append(x)

print(merged_features_list)
dataframe = pd.read_csv('features_merged_30_05_reduced_fixed_list.csv')  
df_processed = prepare_samples(dataframe)
y = df_processed[df_processed.columns[::124]]
y = y.drop(columns = 'All_pairs_count')
X = df_processed[merged_features_list]
X = X.drop(columns = 'class2')
y = pd.get_dummies(data = y, columns = ['class2'])

print(X)
print(y)

model = load_model('multiclass_classification_model.h5')

labels_list = ['ARP_spoofing', 'Docker', 'Exploit', 'Hydra', 'Nmap_sV', 'Regular_traffic', 'SQL_injection'] 
_, accuracy_test = model.evaluate(X, y)
y_pred = model.predict(X)
y_pred_rounded = np.round(y_pred, 2)
y_pred_df = pd.DataFrame(data=y_pred_rounded, columns = labels_list )
y_pred_df['predicted_class'] = y_pred_df.idxmax(axis=1)
predictions = y_pred_df['predicted_class'] 

for prediction in predictions:
    message = message_dict[prediction]
    my_logger.debug('Threat detection module: ' + message)
    time.sleep(1)
    