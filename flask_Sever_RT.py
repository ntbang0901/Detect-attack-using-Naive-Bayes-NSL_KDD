from flask import Flask, render_template, request
from pusher import Pusher
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split
import numpy as np
import pickle


app = Flask(__name__)

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


# configure pusher object
puser = Pusher(
    app_id="1646380",
    key="4ffaf8d3702be38b0e7b",
    secret="53dc374f10e73ba3c69f",
    cluster="us3",
    ssl=True,
)


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

with open("randomfprest2.pkl", "rb") as f:
    nb_model = pickle.load(f)

encoder = OneHotEncoder(sparse=False)
cat_cols = ["protocol_type", "service", "flag"]


@app.route("/detect", methods=["GET", "POST"])
def detect():
    post_data = request.get_json()
    data = post_data["payload"]
    puser_data = data.copy()
    attack_column = "outcome"
    # data = data.fillna(0)
    data = pd.DataFrame([data], columns=datacols, index=[0])
    print(data)
    data["outcome"] = data[attack_column].replace(attack_dict)
    test_data_encoded = pd.DataFrame(encoder.fit_transform(data[cat_cols]))

    feature_names = encoder.get_feature_names_out(cat_cols)
    test_data_encoded.columns = feature_names
    # Drop the original categorical columns from the test_data dataframe
    test_data = data.drop(cat_cols, axis=1)

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
    X_test_handled = handle_missing_features(x, nb_model.feature_names_in_)
    y_test_pred = nb_model.predict(X_test_handled)
    a = np.array(y_test_pred)
    unique, counts = np.unique(a, return_counts=True)
    result = dict(zip(unique, counts))
    print("result", result)

    puser.trigger(
        "detect",
        "push",
        {
            "protocol_type": puser_data["protocol_type"],
            "service": puser_data["service"],
            "flag": puser_data["flag"],
            "src_ip": puser_data["src_ip"],
            "src_port": puser_data["src_port"],
            "dst_ip": puser_data["dst_ip"],
            "dst_port": puser_data["dst_port"],
            "ltime": puser_data["ltime"],
            "detect": "".join(result.keys()),
        },
    )
    key = "normal"
    event = "normal" if key in result.keys() else "attack"
    puser.trigger(
        event,
        "push",
        {
            "detect": "".join(result.keys()),
        },
    )

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
    app.run(host="192.168.2.25", debug=True)
