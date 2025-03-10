# Detecting DDoS Attacks in SDN using Machine Learning

## Overview
This project implements a DDoS attack detection system in Software-Defined Networking (SDN) using Machine Learning. The model is trained using scikit-learn and integrated into the Ryu controller to monitor and block malicious traffic in a Mininet-based network topology.


<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Features
- **Machine Learning-based Detection**: Trained an AI model using scikit-learn with DDoS attack data.
- **Traffic Classification**: Identifies and blocks malicious packets while allowing normal traffic.
- **Integration with Ryu Controller**: Uses a trained model to make real-time traffic decisions.
- **Mininet Topology**: Simulates an SDN environment for testing.

## Installation
### Built With
* [![Python3.X][Python]][https://www.python.org/]]
* [![Ryu][RYU][https://ryu-sdn.org/]]
* [![Mininet][Mininet][https://mininet.org/]]
* [![Scikit-Learn][Scikit-Learn][https://scikit-learn.org/]]
* [![Pandas][Pandas][https://pandas.pydata.org/]]
* [![Numpy][Numpy][https://numpy.org/]]
* [![JobLib][JobLib][https://joblib.readthedocs.io/]]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Acknowledgments
### Files and Structure

├── SDN_DDOS.ipynb      # Google Colab file for training the ML model
├── DDOS_DETECT.py      # Ryu controller script with ML integration
├── Topo.py             # Mininet topology script
├── requirements.txt    # Required Python librarie
└── MODELS 
   ├── AL_MOD.pkl # Saved ML model
   ├── AL_SC.pkl # Saved ML scaler
   ├── NEW_MOD.pkl # Saved ML model
   └── NEW_SC.pkl # Saved ML scaler

### Training
**Run the script:** Execute the python script.  The script performs the following steps:
    - Loads and preprocesses the data.
    - Splits the data into training and testing sets.
    - Trains a RandomForestClassifier model.
    - Evaluates the model using classification metrics and a confusion matrix.
    - Saves the trained model and scaler to disk.
<p align="right">(<a href="SDN_PJT.ipynb">FILE</a>)</p>

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
ryu-manager DDOS_DETECT.py
```
3. start Mininet :
```sh
python3 Topo.py
```
** Now you can launch DOS ATTACK
## License

Distributed under the Mit License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
