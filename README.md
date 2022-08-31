# AI-based-threat-detection
To install requirements run: 
pip install -r requirements.txt

Install Wireshark and Tshark.

To run Graylog:
navigate to the folder where docker-compose file is saved, run: 
docker-compose up -d

To view Graylog client, open the browser at: 
localhost:9000

Default credentials are (admin, admin)


The threat detection module is the threat_detection.py script, this script runs a pcap file, processes the data, generates predictions and provide them to Graylog. 
