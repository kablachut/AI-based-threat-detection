from keras.models import load_model
import pandas as pd
import numpy as np
from data_prep import prepare_samples
import logging
import graypy
import time

message_dict = {
    'ARP_spoofing': 'Attack detected: ARP Spoofing,',
    'Docker': 'Attack detected: Docker API compromise,',
    'Exploit': 'Attack detected: FTP server vulnerability exploit,', 
    'Hydra': 'Attack detected: SSH credentials bruteforcing,', 
    'Nmap_sV': 'Malicious activity detected: Running Nmap tool for ports scanning,', 
    'Regular_traffic': 'Network traffic looks as usually,', 
    'SQL_injection' : 'Attack detected: SQL injection,'
}

my_logger = logging.getLogger('test_logger')
my_logger.setLevel(logging.DEBUG)

handler = graypy.GELFTCPHandler('localhost', 12201)
my_logger.addHandler(handler)

merged_features_list = []
with open(r'features_multiclass_model.txt', 'r') as fp:
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

model = load_model('multiclass_classification_model.h5')

labels_list = ['ARP_spoofing', 'Docker', 'Exploit', 'Hydra', 'Nmap_sV', 'Regular_traffic', 'SQL_injection'] 
_, accuracy_test = model.evaluate(X, y)
y_pred = model.predict(X)
y_pred_rounded = np.round(y_pred, 2)
y_pred_df = pd.DataFrame(data=y_pred_rounded, columns = labels_list )

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

for index, row in predictions_df.iterrows():
    message = message_dict[row['predicted_class_1']]
    message += ' model\'s confidence ' +  str(round(row['max_pred_val'] * 100, 2)) + '%.'
    if row['max_pred_val'] < 1.0:
        message += ' Predcition with the second highest value is: ' + row['predicted_class_2'] + ", with confidence: " + str(round(row['second_pred_val'] * 100, 2)) + '%.'
    my_logger.debug('Threat detection module: ' + message)
    print(message)
    time.sleep(1)
    
