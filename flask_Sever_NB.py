from flask import Flask, render_template, request, jsonify
from pusher import Pusher
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import numpy as np
import pickle
import random
import time
from winotify import Notification, audio
from bot import send_discord_message
import asyncio
import socket
from dotenv import load_dotenv
import os


app = Flask(__name__)


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


app.config["ATTACK_COUNTER"] = 0


def set_global_variable(value):
    app.config["ATTACK_COUNTER"] = value


def get_global_variable():
    return app.config["ATTACK_COUNTER"]


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

data_train = pd.read_csv("KDDTrain+.txt", sep=",", names=datacols)
data_train.loc[data_train["outcome"] == "normal", "outcome"] = "normal"
data_train.loc[data_train["outcome"] != "normal", "outcome"] = "attack"
data_train.fillna(0)
# configure pusher object


load_dotenv()
PUSHER_ID = os.environ.get("PUSHER_ID")
PUSHER_KEY = os.environ.get("PUSHER_KEY")
PUSHER_SECRET = os.environ.get("PUSHER_SECRET")
PUSHER_CLUSTER = os.environ.get("PUSHER_CLUSTER")

puser = Pusher(
    app_id=PUSHER_ID,
    key=PUSHER_KEY,
    secret=PUSHER_SECRET,
    cluster=PUSHER_CLUSTER,
    ssl=True,
)

MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")


async def send_email(subject, message, to_email):
    from_email = MAIL_USERNAME
    password = MAIL_PASSWORD
    # Tạo đối tượng MIMEMultipart
    msg = MIMEMultipart()
    # Thêm tiêu đề và nội dung email
    msg["Subject"] = subject
    msg.attach(MIMEText(message, "plain"))

    # Khởi tạo đối tượng SMTP server
    server = smtplib.SMTP("smtp.gmail.com", 587)
    # Gửi lệnh EHLO để xác nhận kết nối
    server.ehlo()
    # Start Transport Layer Security (TLS) để mã hóa dữ liệu
    server.starttls()
    # Gửi lại lệnh EHLO sau khi đã khởi động TLS
    server.ehlo()
    # Đăng nhập vào tài khoản email của bạn
    server.login(from_email, password)
    # Gửi email từ địa chỉ nguồn đến địa chỉ đích
    server.sendmail(from_email, to_email, msg.as_string())
    # Đóng kết nối với SMTP server
    server.quit()


def Scaling(df_num, cols):
    std_scaler = RobustScaler()
    std_scaler_temp = std_scaler.fit_transform(df_num)
    std_df = pd.DataFrame(std_scaler_temp, columns=cols)
    return std_df


cat_cols = [
    "is_host_login",
    "protocol_type",
    "service",
    "flag",
    "land",
    "logged_in",
    "is_guest_login",
    "level",
    "outcome",
]


def preprocess(dataframe):
    df_num = dataframe.drop(cat_cols, axis=1)
    num_cols = df_num.columns
    scaled_df = Scaling(df_num, num_cols)

    dataframe.drop(labels=num_cols, axis="columns", inplace=True)
    dataframe[num_cols] = scaled_df[num_cols]

    dataframe.loc[dataframe["outcome"] == "normal", "outcome"] = 0
    dataframe.loc[dataframe["outcome"] != 0, "outcome"] = 1

    dataframe = pd.get_dummies(dataframe, columns=["protocol_type", "service", "flag"])
    return dataframe


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


@app.route("/")
def index():
    return render_template("index.html")


import pickle

with open("model_NB_F.pkl", "rb") as f:
    nb_model = pickle.load(f)

encoder = OneHotEncoder(sparse=False)
data_train = data_train.drop(
    [
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "ltime",
    ],
    axis=1,
)
scaled_train = preprocess(data_train)
scaled_train = scaled_train.drop(["outcome", "level"], axis=1)
feature_names = scaled_train.columns


@app.route("/detect", methods=["POST"])
def detect():
    data_json = request.get_json()

    dataframe = pd.DataFrame.from_records(data_json)
    print(dataframe)

    data = dataframe
    puser_data = data.copy()
    data = data.fillna(0)

    x = data.drop(
        [
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "ltime",
        ],
        axis=1,
    )
    scaled_test = preprocess(x)
    scaled_test = scaled_test.drop(
        ["outcome", "level"],
        axis=1,
    )

    X_test_handled = handle_missing_features(scaled_test, feature_names)
    y_test_pred = nb_model.predict(X_test_handled)
    array = np.array(y_test_pred)
    print(array)
    a = np.array(y_test_pred)
    unique, counts = np.unique(a, return_counts=True)
    result = dict(zip(unique, counts))
    print("result", result)
    key = 0
    print("attack_counter::", get_global_variable())

    for idx, x in enumerate(array):
        dictdata = puser_data.iloc[idx].to_dict()
        if x == 1:
            set_global_variable(get_global_variable() + 1)
            if get_global_variable() > 10:
                message = "Warning Attack"
                toast = Notification(
                    app_id="Warning Attack!",
                    title="Winotify Test Toast",
                    msg=message,
                    icon=r"warning.png",
                )

                toast.set_audio(audio.Default, loop=False)
                toast.show()
                asyncio.run(send_discord_message(message))
                co1 = send_email(
                    "Cảnh báo tấn công", "Cảnh báo tấn công", "ntbang0901@gmail.com"
                )
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError as e:
                    if str(e).startswith("There is no current event loop in thread"):
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    else:
                        raise
                loop.run_until_complete(asyncio.gather(co1))
                loop.close()

                puser.trigger(
                    "message", "send", {"name": "ADMIN", "message": "Cảnh báo tấn công"}
                )
                print("Send mail OK")
                set_global_variable(0)

        puser.trigger(
            "detect",
            "push",
            {
                "protocol_type": dictdata["protocol_type"],
                "service": dictdata["service"],
                "flag": dictdata["flag"],
                "src_ip": dictdata["src_ip"],
                "src_port": dictdata["src_port"],
                "dst_ip": dictdata["dst_ip"],
                "dst_port": dictdata["dst_port"],
                "ltime": dictdata["ltime"],
                "detect": "normal" if key == x else "attack",
            },
        )
        event = "normal" if key == x else "attack"
        puser.trigger(
            event,
            "push",
            {
                "detect": "normal" if key == x else "attack",
            },
        )
        print("CONTER::", get_global_variable())

    return "OK"


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/orders", methods=["POST"])
def order():
    data = request.form
    puser.trigger("order", "place", {"units": data["units"]})
    return "units logged"


@app.route("/message", methods=["POST"])
def message():
    data = request.form
    puser.trigger("message", "send", {"name": data["name"], "message": data["message"]})
    return "message sent"


@app.route("/customer", methods=["POST"])
def customer():
    data = request.form
    puser.trigger(
        "customer",
        "add",
        {
            "name": data["name"],
            "position": data["position"],
            "office": data["office"],
            "age": data["age"],
            "salary": data["salary"],
        },
    )
    return "customer added"


if __name__ == "__main__":
    app.run(host=get_ip_address(), debug=True)
