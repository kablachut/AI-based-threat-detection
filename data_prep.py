import math
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

def fill_up_list(l):
    if isinstance(l, float):
        if math.isnan(l):
            l = []
    print(l)
    n = 5
    if len(l) == n:
        return l
    diff = n - len(l)
    while diff > 0:
        l.append('')
        diff -= 1
    return l


def split_protocols(dataframe):
    dataframe['Top_5_internal_protocols'] = dataframe['Top_5_internal_protocols'].str.replace(']', '')
    dataframe['Top_5_internal_protocols'] = dataframe['Top_5_internal_protocols'].str.replace('[', '')
    dataframe['Top_5_protocols'] = dataframe['Top_5_protocols'].str.replace(']', '')
    dataframe['Top_5_protocols'] = dataframe['Top_5_protocols'].str.replace('[', '')


    dataframe['Top_5_internal_protocols_list'] = dataframe['Top_5_internal_protocols'].str.split(',')
    dataframe['Top_5_protocols_list'] = dataframe['Top_5_protocols'].str.split(',')
    dataframe = dataframe.drop(columns=['Top_5_internal_protocols', 'Top_5_protocols'])
    print(dataframe['Top_5_internal_protocols_list'].to_string())


    dataframe['Top_5_internal_protocols_list'] = dataframe['Top_5_internal_protocols_list'].apply(fill_up_list)
    dataframe['Top_5_protocols_list'] = dataframe['Top_5_protocols_list'].apply(fill_up_list)


    df2 = pd.DataFrame(dataframe['Top_5_internal_protocols_list'].to_list(), columns = ['i_protocol_1', 'i_protocol_2', 'i_protocol_3', 
                                                                                'i_protocol_4', 'i_protocol_5'])
    df1 = pd.DataFrame(dataframe['Top_5_protocols_list'].to_list(), columns = ['protocol_1', 'protocol_2', 'protocol_3', 
                                                                                'protocol_4', 'protocol_5'])

    dataframe_joined = dataframe.join(df2)
    dataframe_joined = dataframe_joined.join(df1)
    print(dataframe_joined)

    dataframe_joined = dataframe_joined.drop(columns=['Top_5_internal_protocols_list', 'Top_5_protocols_list'])
    df_dummies = pd.get_dummies(data = dataframe_joined, columns = ['i_protocol_1', 'i_protocol_2', 'i_protocol_3', 
                                                    'i_protocol_4', 'i_protocol_5', 'protocol_1', 'protocol_2', 
                                                    'protocol_3', 'protocol_4', 'protocol_5' ])
    return df_dummies


def encode_classes(dataframe):
    attacks_dict = {
    'sql_injection': 1,
    'exploit': 2,
    'nmap_sV': 3,
    'hydra': 4,
    'docker_commands': 5,
    'ARP_spoofing': 6,
    'regular_traffic': 0
    }
    dataframe = dataframe.replace({"class": attacks_dict})
    dataframe['class2'] = dataframe['class']
    return dataframe

def prepare_samples(dataframe):
    dataframe = split_protocols(dataframe)
    class2_non_normalized =  dataframe['class']
    dataframe = encode_classes(dataframe)

    # drop unncecessary columns
    dataframe = dataframe.drop(columns = ['class', 'Date', 'Unnamed: 0'])
    # remove nulls
    dataframe = dataframe.fillna(0) 

    print(dataframe)
    x = dataframe.values #returns a numpy array
    # normalize data 
    min_max_scaler = MinMaxScaler()
    x_scaled = min_max_scaler.fit_transform(x)
    df_normalized = pd.DataFrame(x_scaled, columns=dataframe.columns)
    df_normalized['class2'] = class2_non_normalized
    return df_normalized


