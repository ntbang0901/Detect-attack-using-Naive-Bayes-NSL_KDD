import requests
import pandas as pd

datacols = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "outcome",
    "level",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "ltime",
]

attack_dict = {
    "normal": "normal",
    "back": "DoS",
    "land": "DoS",
    "neptune": "DoS",
    "pod": "DoS",
    "smurf": "DoS",
    "teardrop": "DoS",
    "mailbomb": "DoS",
    "apache2": "DoS",
    "processtable": "DoS",
    "udpstorm": "DoS",
    "ipsweep": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "satan": "Probe",
    "mscan": "Probe",
    "saint": "Probe",
    "ftp_write": "R2L",
    "guess_passwd": "R2L",
    "imap": "R2L",
    "multihop": "R2L",
    "phf": "R2L",
    "spy": "R2L",
    "warezclient": "R2L",
    "warezmaster": "R2L",
    "sendmail": "R2L",
    "named": "R2L",
    "snmpgetattack": "R2L",
    "snmpguess": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",
    "worm": "R2L",
    "buffer_overflow": "U2R",
    "loadmodule": "U2R",
    "perl": "U2R",
    "rootkit": "U2R",
    "httptunnel": "U2R",
    "ps": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R",
}

# protocol_type = {'tcp': 1,'udp': 2,'icmp':3}
# flag = { 'OTH':1,'REJ':2,'RSTO':3,'RSTOS0':4,'RSTR':5,'S0':6,'S1':7,'S2':8,'S3':9,'SF':10,'SH':11}
# service = {'aol':1,'auth':2,'bgp':3,'courier':4,'csnet_ns':5,'ctf':6,'daytime':7,'discard':8,'domain':9,'domain_u':10,'echo':11,'eco_i':12,'ecr_i':13,'efs':14,'exec':15,'finger':16,'ftp':17,'ftp_data':18,'gopher':19,'harvest':20,'hostnames':21,'http':22,'http_2784':23,'http_443':24,'http_8001':25,'imap4':26,'IRC':27,'iso_tsap':28,'klogin':29,'kshell':30,'ldap':31,'link':32,'login':33,'mtp':34,'name':35,'netbios_dgm':36,'netbios_ns':37,'netbios_ssn':38,'netstat':39,'nnsp':40,'nntp':41,'ntp_u':42,'other':43,'pm_dump':44,'pop_2':45,'pop_3':46,'printer':47,'private':48,'red_i':49,'remote_job':50,'rje':51,'shell':52,'smtp':53,'sql_net':54,'ssh':55,'sunrpc':56,'supdup':57,'systat':58,'telnet':59,'tftp_u':60,'tim_i':61,'time':62,'urh_i':63,'urp_i':64,'uucp':65,'uucp_path':66,'vmnet':67,'whois':68,'X11':69,'Z39_50':70}
import random

import os
import time


def delete_file_contents(file_path):
    try:
        with open(file_path, "w") as file:
            file.truncate(0)

        print(f"The contents of the file '{file_path}' have been deleted.")
    except IOError as e:
        print(f"Error deleting the contents of the file '{file_path}': {e}")


headers = {"Content-Type": "application/json"}


def call_api_every_5_seconds(api_url):
    file_path = "data.csv"
    while True:
        try:
            file_size = os.path.getsize(file_path)
            if os.path.exists(file_path) and file_size > 0:
                data = pd.read_csv(file_path, sep=",", names=datacols)
                data = data.copy()
                data = data.fillna(0)
                dataset = data.to_json(orient="records")
                print(dataset)

                r = requests.post(api_url, data=dataset, headers=headers)
                if r.status_code == 200:
                    delete_file_contents(file_path)
            else:
                print("File not found")

        except requests.RequestException as e:
            # Xử lý các lỗi liên quan đến kết nối, timeout, ...
            print(f"Error making API call: {e}")

        # Tạm dừng thực thi trong 5 giây
        time.sleep(30)


call_api_every_5_seconds("http://192.168.2.25:5000/detect")
