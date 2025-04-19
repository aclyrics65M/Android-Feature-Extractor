'''
Random Forest Classifier for malware detection
by Aadit Patel
4/17/2025

'''

#imports
import pandas as pd
import csv
import os
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, ConfusionMatrixDisplay
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression


#download files
intents_benign_df = pd.read_csv('intents_merged_benign.csv')
permissions_benign_df = pd.read_csv('permissions_merged_benign.csv')
sensitive_apis_benign_df = pd.read_csv('sensitive_apis_merged_benign.csv')

intents_malicious_df = pd.read_csv('intents_merged_malicious.csv')
permissions_malicious_df = pd.read_csv('permissions_merged_malicious.csv')
sensitive_apis_malicious_df = pd.read_csv('sensitive_apis_merged_malicious.csv')


#Preparing dataset for ML algorithms
benign_df = intents_benign_df.merge(permissions_benign_df, on = 'filename')
benign_df = benign_df.merge(sensitive_apis_benign_df.drop(columns =['name']), on = 'filename')
benign_df['y'] = 0

malicious_df = intents_malicious_df.merge(permissions_malicious_df, on = 'filename')
malicious_df = malicious_df.merge(sensitive_apis_malicious_df.drop(columns =['name']), on = 'filename')
malicious_df['y'] = 1

full_df = pd.concat([benign_df, malicious_df], axis=0).reset_index(drop=True)
full_df.info()

#split result labels from training data
x = full_df.drop(columns=['y', 'filename'])
x = x.fillna(0)
y = full_df['y']
print(x.dtypes)

#train test split
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2)

#fit to random forest classifier
model = RandomForestClassifier(n_estimators=1000, random_state=6)
model.fit(x_train, y_train)
y_pred = model.predict(x_test)




# ======== neural network =========

'''
scaler = StandardScaler()
x_scaled = scaler.fit_transform(x)
x_train, x_test, y_train, y_test = train_test_split(x_scaled, y, test_size=0.2, stratify=y)
'''
model = Sequential([
    Dense(64, activation='relu', input_shape=(x_train.shape[1],)),
    Dense(512, activation='relu'),
    Dropout(0.2),
    Dense(1028, activation='relu'),
    Dropout(0.2),
    Dense(64, activation='relu'),
    Dense(1, activation='sigmoid')
])

model.compile(optimizer='SGD',
              loss='binary_crossentropy',
              metrics=['accuracy'])

model.fit(x_train, y_train, epochs=50, batch_size=32, validation_split=0.2)

y_preds = model.predict(x_test)
y_pred_binary = []
for x in y_preds:
    if x > 0.5:
        y_pred_binary.append(1)
    else:
        y_pred_binary.append(0)



# ===== Support Vector Machine =====

svm_model = SVC(kernel='rbf', probability=True)
svm_model.fit(x_train, y_train)
y_pred_svm = svm_model.predict(x_test)

# ====== Logistic Regression ======
log_model = LogisticRegression(max_iter=1000)
log_model.fit(x_train, y_train)
y_pred_log = log_model.predict(x_test)


# ========= Results ==========

#Random forest regressor results
print("\n\n======== Random Forest Regressor Results =========")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision: ", precision_score(y_test,y_pred))
print("Recall: ", recall_score(y_test,y_pred))
print("Confusion matrix: ", confusion_matrix(y_test,y_pred))
print("Full dataset: ")

cd = ConfusionMatrixDisplay(confusion_matrix(y_test,y_pred))
cd.plot()
plt.title('Confusion Matrix Random Forest Regressor')
plt.show()


#Feed forward Neural Network
print("\n\n======== Feed Forward Neural Network Results =========")
print("Accuracy:", accuracy_score(y_test, y_pred_binary))
print("Precision: ", precision_score(y_test,y_pred_binary))
print("Recall: ", recall_score(y_test,y_pred_binary))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_binary))
cd = ConfusionMatrixDisplay(confusion_matrix(y_test,y_pred_binary))
cd.plot()
plt.title('Confusion Matrix Feed Forward Neural Network')
plt.show()

#Support Vector Machines
print("\n\n======== SVM Results =========")
print("Accuracy:", accuracy_score(y_test, y_pred_svm))
print("Precision:", precision_score(y_test, y_pred_svm))
print("Recall:", recall_score(y_test, y_pred_svm))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_svm))
cd = ConfusionMatrixDisplay(confusion_matrix(y_test,y_pred_svm))
cd.plot()
plt.title('Confusion Matrix SVM')
plt.show()

#Logistic Regression
print("\n\n======== Logistic Regressor Results =========")
print("Accuracy:", accuracy_score(y_test, y_pred_log))
print("Precision:", precision_score(y_test, y_pred_log))
print("Recall:", recall_score(y_test, y_pred_log))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_log))
cd = ConfusionMatrixDisplay(confusion_matrix(y_test,y_pred_log))
cd.plot()
plt.title('Confusion Matrix Logistic Regressor')
plt.show()

