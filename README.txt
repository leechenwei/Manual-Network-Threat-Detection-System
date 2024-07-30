This system is a Network Traffic Risk Prediction Tool built using Python's tkinter library for a graphical user interface (GUI) and joblib for loading a pre-trained machine learning model. The tool allows users to input various network traffic features and then predicts the risk level associated with the given network traffic using the trained model.

Features
User Input: The system accepts five numeric input values related to network traffic.
Model Prediction: It utilizes a pre-trained machine learning model to predict the risk based on the user inputs.
Result Display: Predictions are displayed in a new window with color-coded risk levels.

Inputs
The system requires the following input values from the user:

Max Packet Length (in bytes): The maximum length of a packet in the network traffic.
Average Backward Segment Size (in bytes): The average size of backward segments in the network traffic.
Average Packet Size (in bytes): The average size of packets in the network traffic.
Packet Length Standard Deviation (in bytes): The standard deviation of packet lengths in the network traffic.
Max Backward Packet Length (in bytes): The maximum length of backward packets in the network traffic.

Training Model Dataset from CICIDS 2017 Dataset: 
https://www.unb.ca/cic/datasets/ids-2017.html 


