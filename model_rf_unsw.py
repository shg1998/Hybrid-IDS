import pandas as pd
import glob
import os
from river import compose, preprocessing, tree, metrics
import pickle
from soft_tree import SoftLabelHoeffdingTree

col_names = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur',
    'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service',
    'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
    'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit',
    'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login',
    'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'attack_cat', 'Label'
]

print("🔍 Searching for UNSW-NB15 CSV files...")
csv_files = sorted(glob.glob('./dataset/UNSW-NB15_[1-4].csv'))
df_list = []
for file in csv_files:
    try:
        temp_df = pd.read_csv(file, header=None, names=col_names, low_memory=False)
    except Exception as e:
        print(f"⚠️ Warning loading {file}: {e}")
        continue
    df_list.append(temp_df)

df_train = pd.concat(df_list, ignore_index=True)
print(f"✅ Merged! Total rows: {len(df_train)}")

df_train['Label'] = pd.to_numeric(df_train['Label'], errors='coerce').fillna(0).astype(int)

# ✅ ویژگی‌های نویزی حذف می‌شوند، بقیه همه حفظ می‌شوند
drop_cols = ['srcip', 'dstip', 'Stime', 'Ltime', 'attack_cat', 'Label']
categorical_cols = ['proto', 'state', 'service']
numerical_cols = [c for c in col_names if c not in drop_cols and c not in categorical_cols and c not in ['sport', 'dsport']]

df_train[numerical_cols] = df_train[numerical_cols].apply(pd.to_numeric, errors='coerce').fillna(0.0)
df_train['proto'] = df_train['proto'].astype(str).str.lower().str.strip().replace('-', 'other').fillna('other')
df_train['service'] = df_train['service'].astype(str).str.lower().str.strip().replace('-', 'other').fillna('other')
df_train['state'] = df_train['state'].astype(str).str.upper().str.strip().replace('-', 'other').fillna('other')

num_pipe = compose.Select(*numerical_cols) | preprocessing.StandardScaler()
cat_pipe = compose.Select(*categorical_cols) | preprocessing.OneHotEncoder()
pipeline = compose.TransformerUnion(num_pipe, cat_pipe) | SoftLabelHoeffdingTree()

metric = metrics.Accuracy()
def prepare_features(row):
    x = {}
    for col in numerical_cols:
        x[col] = float(row[col])
    for col in categorical_cols:
        x[col] = row[col]
    return x

print(f"🚀 Start training on {len(numerical_cols)} numerical features...")
for idx, row in df_train.iterrows():
    x = prepare_features(row)
    y = row['Label']
    y_pred = pipeline.predict_one(x)
    pipeline.learn_one(x, y)
    metric.update(y, y_pred)
    if (idx + 1) % 200000 == 0:
        print(f"📊 Processed {idx+1} samples -> Online Accuracy: {metric.get():.4f}")

print(f"🏆 Final Accuracy: {metric.get():.4f}")

with open('trained_model_unsw.pkl', 'wb') as f:
    pickle.dump(pipeline, f)
print("💾 Model saved to 'trained_model_unsw.pkl'")