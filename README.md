# Detecting DDoS Attacks in SDN using Machine Learning

## Overview
This project implements a DDoS attack detection system in Software-Defined Networking (SDN) using Machine Learning. The model is trained using scikit-learn and integrated into the Ryu controller to monitor and block malicious traffic in a Mininet-based network topology.

## Features
- **Machine Learning-based Detection**: Trained an AI model using scikit-learn with DDoS attack data.
- **Traffic Classification**: Identifies and blocks malicious packets while allowing normal traffic.
- **Integration with Ryu Controller**: Uses a trained model to make real-time traffic decisions.
- **Mininet Topology**: Simulates an SDN environment for testing.

## Files and Structure
```text
├── SDN_DDOS.ipynb      # Google Colab file for training the ML model
├── RYU-CTL.py      # Ryu controller script with ML integration
├── Topo.py             # Mininet topology script
├── requirements.txt    # Required Python librarie
└── MODELS 
   ├── AL_MOD.pkl # Saved ML model
   ├── AL_SC.pkl # Saved ML scaler
   ├── NEW_MOD.pkl # Saved ML model
   └── NEW_SC.pkl # Saved ML scaler
```
## Dependencies

[![Python](https://img.shields.io/badge/Python-3.X-blue?logo=python)](https://www.python.org/)
[![Ryu](https://img.shields.io/badge/Ryu-SDN-blue?logo=ryu)](https://ryu-sdn.org/)
[![Mininet](https://img.shields.io/badge/Mininet-Networking-blue?logo=mininet)](https://mininet.org/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML-orange?logo=scikit-learn)](https://scikit-learn.org/)
[![Pandas](https://img.shields.io/badge/Pandas-Data-blue?logo=pandas)](https://pandas.pydata.org/)
[![Numpy](https://img.shields.io/badge/Numpy-Math-blue?logo=numpy)](https://numpy.org/)
[![JobLib](https://img.shields.io/badge/JobLib-Performance-green?logo=joblib)](https://joblib.readthedocs.io/)
## Training

The <a href="SDN_PJT.ipynb">SDN_DDOS.ipynb</a> file, follow these steps:

1. **Load and Preprocess the Data**  
   The script begins by loading the dataset and applying necessary preprocessing techniques to prepare the data for modeling.

2. **Split the Data**  
   The dataset is then divided into training and testing sets to ensure that the model can be effectively evaluated on unseen data.

3. **Train the Model**  
   A `RandomForestClassifier` model is trained using the training set, allowing it to learn from the provided features and labels.

4. **Evaluate the Model**  
   After training, the model's performance is assessed using classification metrics, such as accuracy, precision, recall, and F1-score. A confusion matrix is also generated to visualize the model's predictions versus the actual labels.

5. **Save the Model and Scaler**  
   Finally, the trained model and the scaler used for preprocessing are saved to disk for future use, ensuring that you can easily load and utilize them without retraining.

### Model Evaluation

The script generates a classification report and a confusion matrix to evaluate the model's performance. The metrics include:

* Precision
* Recall
* F1-score
* Accuracy
* Confusion matrix visualization

### Model Saving and Loading

The trained model and the StandardScaler used for feature scaling are saved using `joblib`.  The script also demonstrates loading the saved model and using it for prediction.

## Usage
 1. Install dependencies:
```sh
pip install -r requirements.txt
```
2. Run Ryu-controller:
```sh
ryu-manager RYU-CTL.py
```
3. start Mininet :
```sh
python3 Topo.py
```
** Now you can launch DDOS ATTACK
## License

Distributed under the Mit License. See `LICENSE.txt` for more information.
