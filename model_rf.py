import pandas as pd
from river import compose, preprocessing, tree, metrics
import pickle
import inspect
from river import tree

from soft_tree import SoftLabelHoeffdingTree

# print(inspect.getsource(tree.HoeffdingTreeClassifier.learn_one))

# print(inspect.signature(tree.HoeffdingTreeClassifier.learn_one))

col_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label'
]

df_train = pd.read_csv('./datasets/All_Traffic_NSL-KDD.csv', names=col_names)
df_train['label'] = df_train['label'].apply(lambda x: 0 if x == 'normal' else 1)

categorical_cols = ['protocol_type', 'service', 'flag']
numerical_cols = [c for c in col_names if c not in categorical_cols + ['label']]

num_pipe = compose.Select(*numerical_cols) | preprocessing.StandardScaler()
cat_pipe = compose.Select(*categorical_cols) | preprocessing.OneHotEncoder()

pipeline = compose.TransformerUnion(num_pipe, cat_pipe) | SoftLabelHoeffdingTree()

metric = metrics.Accuracy()

def prepare_features(row):
    x = {}
    for col in numerical_cols:
        x[col] = row[col]
    for col in categorical_cols:
        x[col] = row[col]
    return x

print("Start training...")
for idx, row in df_train.iterrows():
    x = prepare_features(row)
    y = row['label']

    y_pred = pipeline.predict_one(x)
    pipeline.learn_one(x, y)
    metric.update(y, y_pred)

    if (idx + 1) % 1000 == 0:
        print(f"Processed {idx+1} samples - Accuracy: {metric.get():.4f}")

print(f"Final training accuracy: {metric.get():.4f}")

with open('trained_model2.pkl', 'wb') as f:
    pickle.dump(pipeline, f)
print("Model saved to 'trained_model2.pkl'")

# Load the model if needed
# with open('trained_model.pkl', 'rb') as f:
#     loaded_model = pickle.load(f)
# print("Model loaded successfully")
