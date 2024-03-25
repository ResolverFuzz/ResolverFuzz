import os

from cache_analyzer import CacheAnalyzer

########################################################################################################################

res_folder_path = '/home/xuesong/proj/ResolverFuzz/test_infra/cdns_test_res'

# Forward-only mode
count_overall = {}
count_diff = {}
index_forward_fallback = []
index_forward_only = []
index_recursive = []
index_alexa = []
total = pos = valid = 0
try:
    if os.path.isdir(res_folder_path):
        for s in os.listdir(res_folder_path):
            if not s.startswith("conf"):
                dir_layer_1 = os.path.join(res_folder_path, s)
                if os.path.isdir(dir_layer_1):
                    for m in os.listdir(dir_layer_1):
                        test = CacheAnalyzer(directory=dir_layer_1, index=m)
                        total += 1
                        if test.res is not None:
                            valid += 1
                            if test.mode not in count_overall:
                                count_overall[test.mode] = 1
                            else:
                                count_overall[test.mode] += 1
                            if len(test.res):
                                if test.mode not in count_diff:
                                    count_diff[test.mode] = 1
                                else:
                                    count_diff[test.mode] += 1
                                if test.mode == "alexa_domain":
                                    index_alexa.append((dir_layer_1, m))
                                elif test.mode == "forward_only":
                                    index_forward_only.append((dir_layer_1, m))
                                elif test.mode == "forward_fallback":
                                    index_forward_fallback.append((dir_layer_1, m))
                                elif test.mode == "recursive":
                                    index_recursive.append((dir_layer_1, m))
                                pos += 1
except KeyboardInterrupt:
    pass
print("\n", '^' * 20, "Exiting...")
print("In the total of " + str(total) + ", there are " + str(pos) + " data points with diff cache.")

########################################################################################################################

index_rec_fb = index_forward_fallback + index_recursive
index_all = index_forward_fallback + index_recursive + index_forward_only
res_count = []


index_target = index_all
for i in index_target:
    test = CacheAnalyzer(directory=i[0], index=i[1])
    res_count.append(test.calc_count())

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans, BisectingKMeans
from sklearn.metrics import silhouette_score, calinski_harabasz_score
import matplotlib.pyplot as plt

df = pd.DataFrame(res_count)

########################################################################################################################
# choose k
SSE = [] # sum of squared error (SSE)
Scores_CH = []  # calinski_harabasz_score
for k in range(2, 50):
    estimator = KMeans(n_clusters=k)
    estimator.fit(np.array(df))
    SSE.append(estimator.inertia_)
    Scores_CH.append(calinski_harabasz_score(np.array(df), estimator.labels_))
# X = range(2, 50)
# plt.xlabel('k')
# plt.ylabel('SSE')
# plt.plot(X, SSE, 'o-')
# plt.show()
X = range(2, 22)
plt.figure(figsize=(14, 7))
plt.xlabel('k', fontsize=24, weight='bold')
plt.ylabel('SSE', fontsize=24, weight='bold')
plt.plot(X, SSE[:20], 'o-')
# plt.xticks(range(2,22), fontsize=24)
# plt.yticks(range(0, 40050, 5000), fontsize=24)
# plt.axis([1, 22, -50, 40050])
# plt.annotate(text='K selected', xy=(7, SSE[6]), xytext=(9, 20000), fontsize=28, weight='bold', color='r', arrowprops=dict(facecolor='c', shrink=0.01))
plt.show()

plt.savefig("k_means.pdf", dpi=500, bbox_inches='tight')

X = range(2, 50)
plt.xlabel('k')
plt.ylabel('calinski_harabasz_score')
plt.plot(X, Scores_CH, 'o-')
plt.show()
X = range(2, 22)
plt.xlabel('k')
plt.ylabel('calinski_harabasz_score')
plt.plot(X, Scores_CH[:20], 'o-')
plt.show()

# choose k using Silhouette Coefficient
Scores = []
for k in range(2, 100):
    estimator = KMeans(n_clusters=k)
    estimator.fit(np.array(df))
    Scores.append(silhouette_score(np.array(df), estimator.labels_, metric='euclidean'))
X = range(2, 100)
plt.xlabel('k')
plt.ylabel('Silhouette Coefficient')
plt.plot(X, Scores, 'o-')
plt.show()
X = range(2, 22)
plt.xlabel('k')
plt.ylabel('Silhouette Coefficient')
plt.plot(X, Scores[:20], 'o-')
plt.show()

########################################################################################################################


n_cluster = 7
cluster = BisectingKMeans(n_clusters=n_cluster)
cluster.fit(np.array(df))

a = cluster.predict(np.array(df))

cluster_res = [[] for i in range(n_cluster)]
for i in range(len(a)):
    cluster_res[a[i]].append(list(np.array(df)[i]))

for i in range(n_cluster):
    df_cluster = pd.DataFrame(cluster_res[i])
    print(df_cluster.describe())
    hist = df_cluster.hist(bins=25, range=[0, 25])
    x = range(25)
    plt.subplot(2, 2, 1)
    plt.xticks(x)
    plt.subplot(2, 2, 2)
    plt.xticks(x)
    plt.subplot(2, 2, 3)
    plt.xticks(x)
    plt.subplot(2, 2, 4)
    plt.xticks(x)
    plt.show()

cluster_res = [[] for i in range(n_cluster)]
for i in range(len(cluster.labels_)):
    cluster_res[cluster.labels_[i]].append(CacheAnalyzer(directory=index_target[i][0], index=index_target[i][1]))

########################################################################################################################
