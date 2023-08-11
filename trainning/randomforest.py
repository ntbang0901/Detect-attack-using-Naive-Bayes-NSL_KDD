# import pandas as pd
# from sklearn.ensemble import RandomForestClassifier, VotingClassifier
# from sklearn.preprocessing import OneHotEncoder
# from sklearn.naive_bayes import GaussianNB
# from sklearn.model_selection import train_test_split
import requests
from sklearn.metrics import accuracy_score, precision_score, recall_score

# import numpy as np

# # Đọc dữ liệu huấn luyện từ file CSV
# datacols = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot'
# ,'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations'
# ,'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count','serror_rate'
# ,'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count'
# ,'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate'
# ,'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','outcome','level']

# train_data = pd.read_csv("KDDTrain+.txt",sep=",", names=datacols)

# X_train = train_data
# y_train_outcome = train_data["outcome"]

# # Mã hóa one-hot cho các biến đặc trưng kiểu chuỗi
# cat_cols = ["protocol_type", "service", "flag","outcome"]
# encoder = OneHotEncoder(sparse=False)
# X_train_encoded = pd.DataFrame(encoder.fit_transform(X_train[cat_cols]))

# # Get the feature names after encoding
# feature_names = encoder.get_feature_names_out(cat_cols)
# X_train_encoded.columns = feature_names

# # Combine the encoded features with numerical features
# X_train_final = pd.concat([X_train.drop(cat_cols, axis=1), X_train_encoded], axis=1)

# X_train, X_test, y_train, y_test = train_test_split(X_train_final, y_train_outcome, test_size=0.2, random_state=42)
# # Train the RandomForestClassifier model
# # Huấn luyện mô hình RandomForestClassifier
# rf_model = RandomForestClassifier()
# nb_model = GaussianNB()
# model = VotingClassifier(estimators=[('rf', rf_model), ('nb', nb_model)], voting='hard')
# model.fit(X_train, y_train)

# # Tạo dữ liệu gói tin mới
# test_data = pd.read_csv("data.csv",sep=",", names=datacols)
# test_data = test_data.drop(["outcome", "level"], axis=1)

# # Encode the new packet using the same encoder
# test_data_encoded = pd.DataFrame(encoder.transform(test_data[cat_cols]))
# test_data_encoded.columns = feature_names

# # Combine the encoded features with numerical features in the new packet
# test_data_final = pd.concat([test_data.drop(cat_cols, axis=1), test_data_encoded], axis=1)

# # Predict the outcome for the new packet
# # y_train_pred = model.predict(X_train)
# y_test_pred  = model.predict(test_data_final)

# print(np.unique(y_test_pred))

import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split
import numpy as np
import pickle

# Đọc dữ liệu huấn luyện từ file CSV
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

data = pd.read_csv("KDDTrain+.txt", sep=",", names=datacols)
test_data = pd.read_csv("data.csv", sep=",", names=datacols)
# test_data = pd.read_csv("KDDTest+.txt", sep=",", names=datacols)

# Chọn cột chứa loại tấn công (attack type) trong dữ liệu
attack_column = "outcome"

# Tạo một bản sao của dữ liệu để thay đổi nhãn
train_data = data.copy()

train_data["outcome"] = train_data[attack_column].replace(attack_dict)
test_data["outcome"] = test_data[attack_column].replace(attack_dict)

train_data = train_data.fillna(0)
test_data = test_data.fillna(0)
train_data.head()
train_data.info()
# traversing through dataframe
# protocol_type,flag, service column and writing
# values where key matches
# def convert_data(data):
#     data.protocol_type = [protocol_type[item] for item in data.protocol_type]
#     data.flag = [flag[item] for item in data.flag]
#     data.service = [service[item] for item in data.service]
#     print(data)
#     data.head()
#     return data

# train_data = convert_data(train_data)
# test_data = convert_data(test_data)
# printing the head of the dataset


cat_cols = ["protocol_type", "service", "flag"]
encoder = OneHotEncoder(sparse=False)
train_data_encoded = pd.DataFrame(encoder.fit_transform(train_data[cat_cols]))

feature_names = encoder.get_feature_names_out(cat_cols)
train_data_encoded.columns = feature_names

# Drop the original categorical columns from the train_data dataframe
train_data = train_data.drop(cat_cols, axis=1)

# Kết hợp các đặc trưng đã mã hóa với các đặc trưng số học
train_data_final = pd.concat([train_data, train_data_encoded], axis=1)

X_train = train_data_final.drop(
    [
        "outcome",
        "level",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "ltime",
    ],
    axis=1,
)
y_train_outcome = train_data_final["outcome"]

X_train, X_test, y_train, y_test = train_test_split(
    X_train, y_train_outcome, test_size=0.2, random_state=42
)

with open("randomfprest2.pkl", "rb") as f:
    nb_model = pickle.load(f)

# model = RandomForestClassifier()
# nb_model.fit(X_train, y_train)


# y_test_pred = nb_model.predict(X_test)

# --------------TEST--------------


def handle_missing_features(data, train_encoded_columns):
    # Get the columns in X_train that are not present in data
    missing_features = set(train_encoded_columns) - set(data.columns)
    missing_features = list(missing_features)

    # Create a DataFrame with missing features and fill with zeros
    missing_df = pd.DataFrame(0, index=data.index, columns=missing_features)

    # Concatenate the new DataFrame with the original data, specifying the column order
    new_data = pd.concat([data, missing_df], axis=1)

    # Reorder the columns in the same order as in X_train
    new_data = new_data[train_encoded_columns]

    return new_data


test_data_encoded = pd.DataFrame(encoder.fit_transform(test_data[cat_cols]))

feature_names = encoder.get_feature_names_out(cat_cols)
test_data_encoded.columns = feature_names
payloaddata = test_data.copy()
# Drop the original categorical columns from the test_data dataframe
test_data = test_data.drop(cat_cols, axis=1)

# Kết hợp các đặc trưng đã mã hóa với các đặc trưng số học
test_data_final = pd.concat([test_data, test_data_encoded], axis=1)

x = test_data_final.drop(
    [
        "outcome",
        "level",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "ltime",
    ],
    axis=1,
)
y_test_outcome = test_data_final["outcome"]
info_test = np.array(y_test_outcome)
unique, counts = np.unique(info_test, return_counts=True)

result_info_test = dict(zip(unique, counts))
print(result_info_test)

train_encoded_columns = X_train.columns

X_test_handled = handle_missing_features(x, train_encoded_columns)

import random
import time
from winotify import Notification, audio
from bot import send_discord_message
import asyncio


def random_data_from_test(data, duration):
    while True:
        # Lấy một chỉ mục dòng ngẫu nhiên từ test_data
        random_index = random.choice(data.index)
        random_row = data.loc[random_index]
        data_test_index = payloaddata.loc[random_index]
        print(data_test_index)
        # Thực hiện công việc của bạn với dòng dữ liệu ngẫu nhiên ở đây
        random_row_2d = np.array([random_row])

        y_test_pred = nb_model.predict(random_row_2d)

        a = np.array(y_test_pred)
        unique, counts = np.unique(a, return_counts=True)
        result = dict(zip(unique, counts))

        # dataset = data_test_index.to_dict()
        # post_data = {
        #     "dataset ID": "makis",
        #     "date start": "1",
        #     "date end": "2",
        #     "payload": dataset,
        # }
        # url = "http://127.0.0.1:5000/detect"
        # r = requests.post(url, json=post_data)
        key = "normal"
        if key not in result.keys():
            print(result)
            message = "Warning Attack: " + "".join(result.keys())
            toast = Notification(
                app_id="Warning Attack!",
                title="Winotify Test Toast",
                msg=message,
                icon=r"d:/TAILIEU/KH2_4/ATMNC/server_python/warning.png",
            )

            toast.set_audio(audio.Default, loop=False)
            toast.show()
            asyncio.run(send_discord_message(message))
        # Pause trong 3 giây trước khi lấy dòng dữ liệu tiếp theo
        time.sleep(duration)


# Assuming you already have the test_data DataFrame

# Gọi hàm với test_data để lấy dữ liệu ngẫu nhiên mỗi 3 giây


# random_data_from_test(X_test_handled, 5)

y_test_pred = nb_model.predict(X_test_handled)
a = np.array(y_test_pred)
unique, counts = np.unique(a, return_counts=True)
result = dict(zip(unique, counts))
print(result)

# --------------TEST--------------


# export_model_path = "randomfprest2.pkl"
#     # Xuất model nếu được chỉ định đường dẫn
# if export_model_path is not None:
#     with open(export_model_path, 'wb') as f:
#         pickle.dump(nb_model, f)
#     with open(export_model_path, 'rb') as f:
#         gnb_loaded= pickle.load(f)
#         print("result:", gnb_loaded)
#     print("Exported model saved successfully at:", export_model_path)

# Tính toán các độ đo
# accuracy = accuracy_score(y_test, y_test_pred)
# precision = precision_score(y_test, y_test_pred, average='weighted')
# recall = recall_score(y_test, y_test_pred, average='weighted')

# # In kết quả
# print("Accuracy:", accuracy)
# print("Precision:", precision)
# print("Recall:", recall)

# y_test_pred = nb_model.predict(test_data_final)

# print(np.unique(y_test_pred))
# a = np.array(y_test_pred)
# unique, counts = np.unique(a, return_counts=True)

# print(dict(zip(unique, counts)))
# result = dict(zip(unique, counts))
# result.pop("normal")
# print(len(result))


# Lấy tên các đặc trưng sau khi mã hóa
# feature_names = encoder.get_feature_names_out(cat_cols)
# X_train_encoded.columns = feature_names

# Kết hợp các đặc trưng đã mã hóa với các đặc trưng số học
# X_train_final = pd.concat([X_train.drop(cat_cols, axis=1), X_train_encoded], axis=1)

# X_train, X_test, y_train, y_test = train_test_split(X_train_final, y_train_outcome, test_size=0.2, random_state=42)

# Huấn luyện mô hình RandomForestClassifier
# rf_model = GaussianNB()
# rf_model.fit(X_train, y_train)

# # Tạo dữ liệu gói tin mới
# test_data = pd.read_csv("data.csv", sep=",", names=datacols)
# test_data = test_data.drop(["outcome", "level"], axis=1)

# # Mã hóa gói tin mới bằng cùng bộ mã hóa
# test_data_encoded = pd.DataFrame(encoder.transform(test_data[cat_cols]))
# test_data_encoded.columns = feature_names

# # Kết hợp các đặc trưng đã mã hóa với các đặc trưng số học trong gói tin mới
# test_data_final = pd.concat([test_data.drop(cat_cols, axis=1), test_data_encoded], axis=1)

# # Dự đoán kết quả cho gói tin mới
# y_test_pred = rf_model.predict(test_data_final)

# print(y_test_pred)


# # Tính toán các độ đo cho tập huấn luyện
# train_accuracy = accuracy_score(y_train, y_train_pred)
# train_precision = precision_score(y_train, y_train_pred, average='weighted')
# train_recall = recall_score(y_train, y_train_pred, average='weighted')

# # Tính toán các độ đo cho tập kiểm tra
# test_accuracy = accuracy_score(y_test, y_test_pred)
# test_precision = precision_score(y_test, y_test_pred, average='weighted')
# test_recall = recall_score(y_test, y_test_pred, average='weighted')

# # In kết quả
# print("Training Accuracy:", train_accuracy)
# print("Training Precision:", train_precision)
# print("Training Recall:", train_recall)
# print("Test Accuracy:", test_accuracy)
# print("Test Precision:", test_precision)
# print("Test Recall:", test_recall)
