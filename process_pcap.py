import pandas as pd
import numpy as np
import logging
import time
import pyshark
import math
from sklearn.preprocessing import MinMaxScaler


def highest_layer(packet):
    layer = packet.layers[-1].layer_name.upper()
    if layer.startswith('DATA'):
        layer = packet.layers[-2].layer_name.upper()
    return layer


def get_ports(packet):
    if hasattr(packet, 'tcp'):
        return(packet.tcp.srcport, packet.tcp.dstport)
    if hasattr(packet, 'udp'):
        return(packet.udp.srcport, packet.udp.dstport)
    return 


def read_pcap_to_df(file_path):
    capture = pyshark.FileCapture(file_path)
    capture_summaries = pyshark.FileCapture(file_path, only_summaries=True)

    protocol_list = []
    timestamp_list = []
    src_dst_list = []
    src_port_list = []
    dst_port_list = [] 
    length_list = []
    http_method_list = []
    http_response_list = []

    for packet in capture:
        protocol = highest_layer(packet)
        ports = get_ports(packet)
        if hasattr(packet, 'http'):
            try:
                method = packet.http.request_method
            except Exception as e:
                print(e)
                method = ''
            try:
                response_code = packet.http.response_code
            except Exception as e:
                print(e)
                response_code = ''
        else:
            method = ''
            response_code = ''

        http_method_list.append(method)
        http_response_list.append(response_code) 
        protocol_list.append(protocol) 
        timestamp_list.append(packet.sniff_time)
        if ports is not None:
            src_port_list.append(ports[0])
            dst_port_list.append(ports[1])
        else:
            src_port_list.append(None)
            dst_port_list.append(None)

    timestamp_list.pop(0)
    protocol_list.pop(0)
    src_port_list.pop(0)
    dst_port_list.pop(0)
    http_method_list.pop(0)
    http_response_list.pop(0)

    for summary in capture_summaries:
        src_dst_list.append(summary.source + ' -> ' + summary.destination)
        length_list.append(summary.length)

    capture.close()
    capture_summaries.close()

    length_list = list(map(int, length_list))
    timeseries_data = {
        'Date': timestamp_list,
        'Protocol': protocol_list,
        'Pair': src_dst_list,
        'Src_port': src_port_list,
        'Dst_port': dst_port_list,
        'Length': length_list,
        'HTTP_method': http_method_list,
        'HTTP_response': http_response_list
    }

    # assemble the dataframe 
    dataframe = pd.DataFrame(timeseries_data, columns=['Date','Protocol', 'Pair','Src_port', 'Dst_port', 'Length', 'HTTP_method', 'HTTP_response'])
    return dataframe

def fill_up_list(l):
    print(l)
    if isinstance(l, float):
        if math.isnan(l):
            l = []
    if not isinstance(l, list):     
        l = l.tolist()
    n = 5
    if len(l) == n:
        return l
    diff = n - len(l)
    while diff > 0:
        l.append('')
        diff -= 1
    return l


def split_protocols(dataframe):
    dataframe['Top_5_internal_protocols_list'] = dataframe['Top_5_internal_protocols'].values.tolist()
    dataframe['Top_5_protocols_list'] = dataframe['Top_5_protocols'].values.tolist()

    dataframe['Top_5_internal_protocols_list'] = dataframe['Top_5_internal_protocols_list'].apply(fill_up_list)
    dataframe['Top_5_protocols_list'] = dataframe['Top_5_protocols_list'].apply(fill_up_list)
    print(dataframe.head(10))

    df2 = pd.DataFrame(dataframe['Top_5_internal_protocols_list'].to_list(), columns = ['i_protocol_1', 'i_protocol_2', 'i_protocol_3', 
                                                                                'i_protocol_4', 'i_protocol_5'])
    df1 = pd.DataFrame(dataframe['Top_5_protocols_list'].to_list(), columns = ['protocol_1', 'protocol_2', 'protocol_3',  
                                                                                   'protocol_4', 'protocol_5'])
    
    df1 = pd.get_dummies(df1, prefix=['protocol_1', 'protocol_2', 'protocol_3', 'protocol_4', 'protocol_5'])
    df2 = pd.get_dummies(df2, prefix=['i_protocol_1', 'i_protocol_2', 'i_protocol_3', 'i_protocol_4', 'i_protocol_5'])
    
    # reset indices to aviod getting nan values    
    df2.reset_index(drop=True, inplace=True)
    df1.reset_index(drop=True, inplace=True)
    dataframe.reset_index(drop=True, inplace=True)
    
    dataframe_joined = dataframe.join(df2)
    dataframe_joined = dataframe_joined.join(df1)
    dataframe_joined = dataframe_joined.drop(columns=['Top_5_internal_protocols_list', 'Top_5_protocols_list',
                                                      'Top_5_internal_protocols', 'Top_5_protocols'])

    print(dataframe_joined.head(10))
    return dataframe_joined


def generate_features(dataframe, frequency):
    src_dst_splitted = dataframe['Pair'].str.split(" -> ", n = 1, expand = True)
  
    # making separate first name column from new data frame
    dataframe['Src_address']= src_dst_splitted[0]
    # making separate last name column from new data frame
    dataframe['Dst_address']= src_dst_splitted[1]
    
    # resample to certain frequency chunks for internal to external pair count ratio 
    df_all_grouped = dataframe.groupby(['Pair', 'Protocol', pd.Grouper(freq=frequency, key='Date')])['Length'].count()

    df_all_grouped = pd.DataFrame(df_all_grouped).reset_index()
    df_internal_grouped = df_all_grouped.loc[(df_all_grouped['Pair'].str.startswith('172.20.1.') & 
        df_all_grouped['Pair'].str.contains('-> 172.20.1.')) | df_all_grouped['Protocol'].str.startswith('ARP')]

    df_all_grouped_pairs = df_all_grouped.groupby('Date')['Pair'].unique().reset_index()

    df_all_grouped_pairs['All_pairs_count'] = df_all_grouped_pairs['Pair'].str.len()
    df_all_grouped_pairs = df_all_grouped_pairs.drop(columns=['Pair'])

    df_internal_grouped_pairs = df_internal_grouped.groupby('Date')['Pair'].unique().reset_index()

    df_internal_grouped_pairs['Internal_pairs_count'] = df_internal_grouped_pairs['Pair'].str.len()
    df_internal_grouped_pairs = df_internal_grouped_pairs.drop(columns=['Pair'])

    merged_pairs = pd.merge(df_all_grouped_pairs, df_internal_grouped_pairs, on='Date', how='outer')
    merged_pairs ['Pairs_ratio'] = merged_pairs['Internal_pairs_count'] / merged_pairs['All_pairs_count']

    # resample to certain frequency chunks for internal to external packet count ratio and packet length median
    df_all_packet_count = dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_all_packet_count = df_all_packet_count.rename(columns={'Length':'All_packets_count'})

    df_all_packet_mean = dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].mean().reset_index()
    df_all_packet_mean = df_all_packet_mean.rename(columns={'Length':'All_packets_mean'})

    df_all_packet_sum = dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].sum().reset_index()
    df_all_packet_sum = df_all_packet_sum.rename(columns={'Length':'All_packets_sum'})

    df_internal = dataframe.loc[(dataframe['Pair'].str.startswith('172.20.1.') & dataframe['Pair'].str.contains('-> 172.20.1.')) 
                                | dataframe['Protocol'].str.startswith('ARP')]

    df_internal_packet_count =  df_internal.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_internal_packet_count = df_internal_packet_count.rename(columns={'Length':'Internal_packets_count'})

    df_internal_packet_mean =  df_internal.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].mean().reset_index()
    df_internal_packet_mean = df_internal_packet_mean.rename(columns={'Length':'Internal_packets_mean'})

    df_internal_packet_sum = df_internal.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].sum().reset_index()
    df_internal_packet_sum = df_internal_packet_sum.rename(columns={'Length':'Internal_packets_sum'})
 
    df_all_port_dest_count= dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Dst_port'].unique().reset_index()
    df_all_port_dest_count['All_dst_ports_count'] = df_all_port_dest_count['Dst_port'].str.len()
    df_all_port_dest_count = df_all_port_dest_count.drop(columns=['Dst_port'])

    df_all_port_src_count= dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Src_port'].unique().reset_index()
    df_all_port_src_count['All_src_ports_count'] = df_all_port_src_count['Src_port'].str.len()
    df_all_port_src_count = df_all_port_src_count.drop(columns=['Src_port'])

    df_all_ports = pd.merge(df_all_port_src_count, df_all_port_dest_count, on='Date', how='outer')
    df_all_ports['Ports_ratio'] = df_all_ports['All_dst_ports_count'] / df_all_ports['All_src_ports_count']

    # count source addresses
    df_all_add_src_count= dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Src_address'].unique().reset_index()
    df_all_add_src_count['All_src_add_count'] = df_all_add_src_count['Src_address'].str.len()
    df_all_add_src_count = df_all_add_src_count.drop(columns=['Src_address'])

    # destination addresses 
    df_all_add_dest_count= dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Dst_address'].unique().reset_index()
    df_all_add_dest_count['All_dst_add_count'] = df_all_add_dest_count['Dst_address'].str.len()
    df_all_add_dest_count = df_all_add_dest_count.drop(columns=['Dst_address'])

    # TCP internal packets
    df_internal_tcp = df_internal.loc[(df_internal['Protocol'] == 'TCP')]
    df_internal_tcp_count = df_internal_tcp.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_internal_tcp_count = df_internal_tcp_count.rename(columns={'Length':'Internal_TCP_count'})

    # ARP packets
    df_arp = dataframe.loc[(dataframe['Protocol'] == 'ARP')]
    df_arp_count = df_arp.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_arp_count = df_arp_count.rename(columns={'Length':'ARP_count'})

    # SSH internal packets
    df_ssh = dataframe.loc[(dataframe['Protocol'] == 'SSH')]
    df_ssh_count = df_ssh.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_ssh_count = df_ssh_count.rename(columns={'Length':'SSH_count'})

    df_all_small_packets = dataframe.loc[(dataframe['Length'] < 100)]
    df_all_small_packets_count = df_all_small_packets.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_all_small_packets_count = df_all_small_packets_count.rename(columns={'Length':'All_small_packet_count'})

    # packet count per internal source address
    df_packet_count_per_src_add = df_internal.groupby(['Src_address', pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_packet_avg_packet_per_src_add = df_packet_count_per_src_add.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].mean().reset_index()
    df_packet_avg_packet_per_src_add = df_packet_avg_packet_per_src_add.rename(columns={'Length':'Avg_packet_count_per_src_add'})

    # packet count per internal destination address
    df_packet_count_per_dst_add = df_internal.groupby(['Dst_address', pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_packet_avg_packet_per_dst_add = df_packet_count_per_dst_add.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].mean().reset_index()
    df_packet_avg_packet_per_dst_add = df_packet_avg_packet_per_dst_add.rename(columns={'Length':'Avg_packet_count_per_dst_add'})

    # packet count per source port
    df_packet_count_per_src_port = df_internal.groupby(['Src_port', pd.Grouper(freq=frequency, 
                                                                            key='Date')])['Length'].count().reset_index()
    df_packet_avg_packet_per_src_port = df_packet_count_per_src_port.groupby([pd.Grouper(freq=frequency, 
                                                                                key='Date')])['Length'].mean().reset_index()
    df_packet_avg_packet_per_src_port = df_packet_avg_packet_per_src_port.rename(columns={'Length':'Avg_packet_count_per_src_port'})

    # packet count per destination port
    df_packet_count_per_dst_port = df_internal.groupby(['Dst_port', pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_packet_avg_packet_per_dst_port = df_packet_count_per_dst_port.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].mean().reset_index()
    df_packet_avg_packet_per_dst_port = df_packet_avg_packet_per_dst_port.rename(columns={'Length':'Avg_packet_count_per_dst_port'})

    # packet count per internal pair
    df_packet_count_per_pair = df_internal.groupby(['Pair', pd.Grouper(freq=frequency, key='Date') ])['Length'].count().reset_index()
    df_avg_packet_count_per_pair = df_packet_count_per_pair.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].mean().reset_index()
    df_avg_packet_count_per_pair = df_avg_packet_count_per_pair.rename(columns={'Length':'Avg_packet_count_per_pair'})


    dataframe[['HTTP_response','HTTP_method' ]] = dataframe[['HTTP_response','HTTP_method' ]].fillna('')

    # count 5xx codes
    df_http_codes_5xx = dataframe.loc[(dataframe['HTTP_response'].str.match('^5\d{2}\.0$')== True)]
    df_http_5xx_count = df_http_codes_5xx.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_http_5xx_count = df_http_5xx_count.rename(columns={'Length':'HTTP_5xx_count'})

    # count 4xx codes
    df_http_codes_4xx = dataframe.loc[(dataframe['HTTP_response'].str.match('^4\d{2}\.0$')== True)]
    df_http_4xx_count = df_http_codes_4xx.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_http_4xx_count = df_http_4xx_count.rename(columns={'Length':'HTTP_4xx_count'})

    # count other than 'GET', 'POST' methods
    df_other_http_requests = dataframe.loc[((dataframe['HTTP_method'] != 'GET') & (dataframe['HTTP_method'] != 'POST') &  
                                            (dataframe['HTTP_method'] != ''))]
    df_other_http_requests_count = df_other_http_requests.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_other_http_requests_count = df_other_http_requests_count.rename(columns={'Length':'Other_HTTP_count'})

    means_merged = pd.merge(df_all_packet_mean, df_internal_packet_mean, on='Date', how='outer')
    means_merged = pd.merge(means_merged, df_packet_avg_packet_per_src_add, on='Date', how='outer')
    means_merged = pd.merge(means_merged, df_packet_avg_packet_per_dst_add, on='Date', how='outer')
    means_merged = pd.merge(means_merged, df_packet_avg_packet_per_src_port, on='Date', how='outer')
    means_merged = pd.merge(means_merged, df_packet_avg_packet_per_dst_port, on='Date', how='outer')
    means_merged = pd.merge(means_merged, df_avg_packet_count_per_pair, on='Date', how='outer')
    means_merged = means_merged.set_index('Date')

    merged = pd.merge(merged_pairs, df_all_add_src_count, on='Date', how='outer')
    merged = pd.merge(merged, df_all_add_dest_count, on='Date', how='outer')
    merged = pd.merge(merged, df_all_ports, on='Date', how='outer')
    merged = pd.merge(merged, df_all_packet_sum, on='Date', how='outer')
    merged = pd.merge(merged, df_internal_packet_sum, on='Date', how='outer')
    merged = pd.merge(merged, df_all_packet_count, on='Date', how='outer' )
    merged = pd.merge(merged, df_all_small_packets_count, on='Date', how='outer')
    merged = pd.merge(merged, df_internal_packet_count, on='Date', how='outer')
    merged = pd.merge(merged, df_arp_count, on='Date', how='outer' )
    merged = pd.merge(merged, df_internal_tcp_count, on='Date', how='outer')
    merged = pd.merge(merged, df_ssh_count, on='Date', how='outer')
    merged = pd.merge(merged, df_http_5xx_count, on='Date', how='outer')
    merged = pd.merge(merged, df_http_4xx_count, on='Date', how='outer')
    merged = pd.merge(merged, df_other_http_requests_count, on='Date', how='outer')


    merged ['Dst_src_address_ratio'] =  merged['All_dst_add_count'] / merged['All_src_add_count']
    merged ['Packet_count_ratio'] = merged['Internal_packets_count'] / merged['All_packets_count']
    merged ['Packet_sum_ratio'] = merged['Internal_packets_sum'] / merged['All_packets_sum']
    merged ['Small_packet_ratio'] = merged['All_small_packet_count'] / merged['All_packets_count']
    merged ['ARP_packet_ratio'] = merged['ARP_count'] /merged['All_packets_count']
    merged ['TCP_packet_ratio'] = merged['Internal_TCP_count'] /merged['Internal_packets_count']
    merged ['SSH_packet_ratio'] = merged['SSH_count'] /merged['All_packets_count']

    merged = merged.set_index('Date')

    cut_first = 1
    cut_last = 1

    merged = merged.iloc[cut_first: , :]
    merged = merged.iloc[:-cut_last,:]

    means_merged = means_merged.iloc[cut_first: , :]
    means_merged = means_merged.iloc[:-cut_last,:]

    df_top_protocols = get_top5_protocols(dataframe, frequency, internal=False)
    df_top_internal_protocols = get_top5_protocols(df_internal, frequency, internal=True)

    features_merged = pd.merge(merged, means_merged, on='Date', how='outer')
    features_merged = pd.merge(features_merged, df_top_protocols, on='Date', how='outer')
    features_merged = pd.merge(features_merged, df_top_internal_protocols, on='Date', how='outer')
    return features_merged


def get_top5_protocols(dataframe, frequency, internal):
    # top 5 protocols used among all pairs
    df_protocols_count = dataframe.groupby(['Protocol', pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    # print(df_protocols_count.to_string())
    df_top_protocols = df_protocols_count.groupby('Date')['Length'].nlargest(5).reset_index()
    protocol_list = df_protocols_count['Protocol'].iloc[df_top_protocols['level_1']]
    protocol_list = protocol_list.to_frame()
    protocol_list.reset_index(drop=True, inplace=True)

    df_top_protocols['Protocol'] = protocol_list['Protocol']
    df_top_protocols = df_top_protocols.drop(columns=['level_1', 'Length'])
    df_top_protocols = df_top_protocols.groupby('Date')['Protocol'].unique()

    df_top_protocols = df_top_protocols.to_frame()

    if internal: 
        column_name = 'Top_5_internal_protocols'
    else: 
        column_name = 'Top_5_protocols'
    df_top_protocols = df_top_protocols.rename(columns={'Protocol':column_name})

    # remove last and the first interval as they might not carry full time interval defined by frequency 
    df_top_protocols = df_top_protocols.iloc[1: , :]
    df_top_protocols = df_top_protocols.iloc[:-1,:]
    return df_top_protocols

def prepare_samples(dataframe):
    # remove nulls
    dataframe = dataframe.fillna(0) 
    x = dataframe.values #returns a numpy array
    # normalize data 
    min_max_scaler = MinMaxScaler()
    x_scaled = min_max_scaler.fit_transform(x)
    df_normalized = pd.DataFrame(x_scaled, columns=dataframe.columns)
    return df_normalized


def read_training_dataset(file_path):
    # read and prepare training data 
    dataframe = pd.read_csv(file_path)  

    dataframe['Top_5_internal_protocols'] = dataframe['Top_5_internal_protocols'].str.replace(']', '')
    dataframe['Top_5_internal_protocols'] = dataframe['Top_5_internal_protocols'].str.replace('[', '')
    dataframe['Top_5_protocols'] = dataframe['Top_5_protocols'].str.replace(']', '')
    dataframe['Top_5_protocols'] = dataframe['Top_5_protocols'].str.replace('[', '')

    dataframe['Top_5_internal_protocols_list'] = dataframe['Top_5_internal_protocols'].str.split(',')
    dataframe['Top_5_protocols_list'] = dataframe['Top_5_protocols'].str.split(',')
    dataframe = dataframe.drop(columns=['Top_5_internal_protocols', 'Top_5_protocols'])
    
    dataframe['Top_5_internal_protocols_list'] = dataframe['Top_5_internal_protocols_list'].apply(fill_up_list)
    dataframe['Top_5_protocols_list'] = dataframe['Top_5_protocols_list'].apply(fill_up_list)
    print('after filling up list')
    print(dataframe.head(10))

    df2 = pd.DataFrame(dataframe['Top_5_internal_protocols_list'].to_list(), columns = ['i_protocol_1', 'i_protocol_2', 'i_protocol_3', 
                                                                                'i_protocol_4', 'i_protocol_5'])
    df1 = pd.DataFrame(dataframe['Top_5_protocols_list'].to_list(), columns = ['protocol_1', 'protocol_2', 'protocol_3', 
                                                                                'protocol_4', 'protocol_5'])

    dataframe_joined = dataframe.join(df2)
    dataframe_joined = dataframe_joined.join(df1)

    dataframe_joined = dataframe_joined.drop(columns=['Top_5_internal_protocols_list', 'Top_5_protocols_list'])
    df_dummies = pd.get_dummies(data = dataframe_joined, columns = ['i_protocol_1', 'i_protocol_2', 'i_protocol_3', 
                                                    'i_protocol_4', 'i_protocol_5', 'protocol_1', 'protocol_2', 
                                                    'protocol_3', 'protocol_4', 'protocol_5' ])
    df_dummies = df_dummies.drop(columns = ['class', 'Date', 'Unnamed: 0'])

    for col in df_dummies.columns:
        df_dummies.rename(columns={col:col.replace("'","")},inplace=True)

    return df_dummies