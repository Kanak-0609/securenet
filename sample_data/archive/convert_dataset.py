import pandas as pd
import random

random.seed(42)

columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

df = pd.read_csv("KDDTrain.txt", names=columns)

# Take a manageable sample for the dashboard (full 125,973 rows is heavy for a browser table)
df = df.sample(n=8000, random_state=42).reset_index(drop=True)

# Generate realistic-looking source IPs (NSL-KDD doesn't include real IPs)
def random_ip():
    return f"192.168.{random.randint(1,10)}.{random.randint(2,254)}"

out = pd.DataFrame({
    "source_ip": [random_ip() for _ in range(len(df))],
    "packet_size": df["src_bytes"] + df["dst_bytes"],
    "protocol": df["protocol_type"].str.upper(),
    "true_label": df["label"].apply(lambda x: "normal" if x == "normal" else "attack")
})

out.to_csv("traffic_log.csv", index=False)
print(f"Converted {len(out)} rows.")
print(f"Normal: {(out['true_label']=='normal').sum()}, Attacks: {(out['true_label']=='attack').sum()}")
