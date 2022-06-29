import pyshark
import pandas as pd

file_path = 'regular_traffic2_29_04.pcap'
frequency = '30S'
internal_network_prefix = '172.20.1.'


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
    
def read_pcap_to_dataframe(file_path):
    capture = pyshark.FileCapture(file_path)
    capture_summaries = pyshark.FileCapture(file_path, only_summaries=True)
    protocol_list = []
    timestamp_list = []
    src_dst_list = []
    src_address_list = []
    dst_address_list = []
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
        src_address_list.append(summary.source)
        dst_address_list.append(summary.destination)

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
        'HTTP_response': http_response_list,
        'Src_address': src_address_list,
        'Dst_address': dst_address_list
    }
    print(len(length_list))
    print(len(timestamp_list))
    print(len(http_response_list))

    # assemble the dataframe 
    dataframe = pd.DataFrame(timeseries_data, columns=['Date','Protocol', 'Pair','Src_port', 'Dst_port', 'Length', 'HTTP_method', 'HTTP_response','Src_address', 'Dst_address'])
    return dataframe


def generate_features(dataframe):
    # fix datatypes
    dataframe['Date'] = pd.to_datetime(dataframe['Date'])
    dataframe['HTTP_response'] = dataframe['HTTP_response'].astype(str)

    # resample to certain frequency chunks for internal to external pair count ratio 
    df_all_grouped = dataframe.groupby(['Pair', 'Protocol', pd.Grouper(freq=frequency, key='Date')])['Length'].count()
    df_all_grouped = pd.DataFrame(df_all_grouped).reset_index()

    df_internal_grouped = df_all_grouped.loc[(df_all_grouped['Pair'].str.startswith(internal_network_prefix) & df_all_grouped['Pair'].str.contains('-> ' + internal_network_prefix)) | df_all_grouped['Protocol'].str.startswith('ARP')]
    print(df_internal_grouped)

    # count all pairs
    df_all_grouped_pairs = df_all_grouped.groupby('Date')['Pair'].unique().reset_index()
    df_all_grouped_pairs['All_pairs_count'] = df_all_grouped_pairs['Pair'].str.len()
    df_all_grouped_pairs = df_all_grouped_pairs.drop(columns=['Pair'])

    # count internal pairs
    df_internal_grouped_pairs = df_internal_grouped.groupby('Date')['Pair'].unique().reset_index()
    df_internal_grouped_pairs['Internal_pairs_count'] = df_internal_grouped_pairs['Pair'].str.len()
    df_internal_grouped_pairs = df_internal_grouped_pairs.drop(columns=['Pair'])

    # get pairs ratio
    merged_pairs = pd.merge(df_all_grouped_pairs, df_internal_grouped_pairs, on='Date', how='outer')
    merged_pairs ['Pairs_ratio'] = merged_pairs['Internal_pairs_count'] / merged_pairs['All_pairs_count']   

    # resample to certain frequency chunks for internal to external packet count ratio and packet length median
    df_all_packet_count = dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_all_packet_count = df_all_packet_count.rename(columns={'Length':'All_packets_count'})

    # calculate mean length for all packets 
    df_all_packet_mean = dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].mean().reset_index()
    df_all_packet_mean = df_all_packet_mean.rename(columns={'Length':'All_packets_mean'})

    # calculate sum of all packet lengths
    df_all_packet_sum = dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].sum().reset_index()
    df_all_packet_sum = df_all_packet_sum.rename(columns={'Length':'All_packets_sum'})

    # assemble dataframe with just internal packets
    df_internal = dataframe.loc[(dataframe['Pair'].str.startswith('172.20.1.') & dataframe['Pair'].str.contains('-> 172.20.1.')) 
                                | dataframe['Protocol'].str.startswith('ARP')]

    # count all internally sent packets
    df_internal_packet_count =  df_internal.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_internal_packet_count = df_internal_packet_count.rename(columns={'Length':'Internal_packets_count'})

    # calculate mean length for internal packets 
    df_internal_packet_mean =  df_internal.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].mean().reset_index()
    df_internal_packet_mean = df_internal_packet_mean.rename(columns={'Length':'Internal_packets_mean'})
    
    # calculate sum of internal packet lengths
    df_internal_packet_sum = df_internal.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].sum().reset_index()
    df_internal_packet_sum = df_internal_packet_sum.rename(columns={'Length':'Internal_packets_sum'})

    # count all unique destination ports
    df_all_port_dest_count= dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Dst_port'].unique().reset_index()
    df_all_port_dest_count['All_dst_ports_count'] = df_all_port_dest_count['Dst_port'].str.len()
    df_all_port_dest_count = df_all_port_dest_count.drop(columns=['Dst_port'])

    # count all unique source ports 
    df_all_port_src_count= dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Src_port'].unique().reset_index()
    df_all_port_src_count['All_src_ports_count'] = df_all_port_src_count['Src_port'].str.len()
    df_all_port_src_count = df_all_port_src_count.drop(columns=['Src_port'])

    # get ports ratio dst to src
    df_all_ports = pd.merge(df_all_port_src_count, df_all_port_dest_count, on='Date', how='outer')
    df_all_ports['Ports_ratio'] = df_all_ports['All_dst_ports_count'] / df_all_ports['All_src_ports_count']


    # count source addresses
    df_all_add_src_count= dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Src_address'].unique().reset_index()
    df_all_add_src_count['All_src_add_count'] = df_all_add_src_count['Src_address'].str.len()
    df_all_add_src_count = df_all_add_src_count.drop(columns=['Src_address'])

    # count destination addresses 
    df_all_add_dest_count= dataframe.groupby([pd.Grouper(freq=frequency, key='Date')])['Dst_address'].unique().reset_index()
    df_all_add_dest_count['All_dst_add_count'] = df_all_add_dest_count['Dst_address'].str.len()
    df_all_add_dest_count = df_all_add_dest_count.drop(columns=['Dst_address'])
    
    # count internal TCP packets
    df_internal_tcp = df_internal.loc[(df_internal['Protocol'] == 'TCP')]
    df_internal_tcp_count = df_internal_tcp.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_internal_tcp_count = df_internal_tcp_count.rename(columns={'Length':'Internal_TCP_count'})

    # count ARP packets
    df_arp = dataframe.loc[(dataframe['Protocol'] == 'ARP')]
    df_arp_count = df_arp.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_arp_count = df_arp_count.rename(columns={'Length':'ARP_count'})

    # count internal SSH packets
    df_ssh = dataframe.loc[(dataframe['Protocol'] == 'SSH')]
    df_ssh_count = df_ssh.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_ssh_count = df_ssh_count.rename(columns={'Length':'SSH_count'})

    # count all small packets with the length below 100
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

    # replace null HTTP responce codes and request methods 
    dataframe[['HTTP_response','HTTP_method' ]] = dataframe[['HTTP_response','HTTP_method' ]].fillna('')

    # count 5xx HTTP responce codes
    df_http_codes_5xx = dataframe.loc[(dataframe['HTTP_response'].str.match('^5\d{2}\.0$')== True)]
    df_http_5xx_count = df_http_codes_5xx.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_http_5xx_count = df_http_5xx_count.rename(columns={'Length':'HTTP_5xx_count'})

    # count 4xx HTTP responce codes
    df_http_codes_4xx = dataframe.loc[(dataframe['HTTP_response'].str.match('^4\d{2}\.0$')== True)]
    df_http_4xx_count = df_http_codes_4xx.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_http_4xx_count = df_http_4xx_count.rename(columns={'Length':'HTTP_4xx_count'})


    # count other than 'GET', 'POST' HTTP methods
    df_other_http_requests = dataframe.loc[((dataframe['HTTP_method'] != 'GET') & (dataframe['HTTP_method'] != 'POST') &  
                                            (dataframe['HTTP_method'] != ''))]
    df_other_http_requests_count = df_other_http_requests.groupby([pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_other_http_requests_count = df_other_http_requests_count.rename(columns={'Length':'Other_HTTP_count'})


    # merge the calculated features into one dataframe
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

    # get remaining ratios
    merged ['Dst_src_address_ratio'] =  merged['All_dst_add_count'] / merged['All_src_add_count']
    merged ['Packet_count_ratio'] = merged['Internal_packets_count'] / merged['All_packets_count']
    merged ['Packet_sum_ratio'] = merged['Internal_packets_sum'] / merged['All_packets_sum']
    merged ['Small_packet_ratio'] = merged['All_small_packet_count'] / merged['All_packets_count']
    merged ['ARP_packet_ratio'] = merged['ARP_count'] /merged['All_packets_count']
    merged ['TCP_packet_ratio'] = merged['Internal_TCP_count'] /merged['Internal_packets_count']
    merged ['SSH_packet_ratio'] = merged['SSH_count'] /merged['All_packets_count']

    merged = merged.set_index('Date')

    # removing last and first rows, there is a risk they cover less than 30 seconds so are not representative. 
    cut_first = 1
    cut_last = 1

    merged = merged.iloc[cut_first: , :]
    merged = merged.iloc[:-cut_last,:]

    means_merged = means_merged.iloc[cut_first: , :]
    means_merged = means_merged.iloc[:-cut_last,:]


    # get top 5 protocols used among all pairs
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
    df_top_protocols = df_top_protocols.rename(columns={'Protocol':'Top_5_protocols'})
    df_top_protocols = df_top_protocols.iloc[cut_first: , :]
    df_top_protocols = df_top_protocols.iloc[:-cut_last,:]

    # get top 5 protocols used among internal pairs
    df_protocols_internal_count = df_internal.groupby(['Protocol', pd.Grouper(freq=frequency, key='Date')])['Length'].count().reset_index()
    df_top_internal_protocols = df_protocols_internal_count.groupby('Date')['Length'].nlargest(5).reset_index()
    internal_protocol_list = df_protocols_internal_count['Protocol'].iloc[df_top_internal_protocols['level_1']]
    internal_protocol_list = internal_protocol_list.to_frame()
    internal_protocol_list.reset_index(drop=True, inplace=True)

    df_top_internal_protocols['Protocol'] = internal_protocol_list['Protocol']
    df_top_internal_protocols = df_top_internal_protocols.drop(columns=['level_1', 'Length'])
    df_top_internal_protocols = df_top_internal_protocols.groupby('Date')['Protocol'].unique()
    df_top_internal_protocols = df_top_internal_protocols.to_frame()
    df_top_internal_protocols = df_top_internal_protocols.rename(columns={'Protocol':'Top_5_internal_protocols'})
    df_top_internal_protocols = df_top_internal_protocols.iloc[cut_first: , :]
    df_top_internal_protocols = df_top_internal_protocols.iloc[:-cut_last,:]

    # merge all features together
    features_merged = pd.merge(merged, means_merged, on='Date', how='outer')
    features_merged = pd.merge(features_merged, df_top_protocols, on='Date', how='outer')
    features_merged = pd.merge(features_merged, df_top_internal_protocols, on='Date', how='outer')
    return features_merged


df = read_pcap_to_dataframe(file_path)
print(df)

features_df = generate_features(df)
print(features_df)
