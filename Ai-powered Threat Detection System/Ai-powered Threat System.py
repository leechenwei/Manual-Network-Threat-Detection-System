import tkinter as tk
from tkinter import messagebox
import pandas as pd
import joblib

# Load the trained model
pipeline = joblib.load('network_traffic_model.pkl')

# Define the top 5 features
top_features = [
    'Max Packet Length', 'Avg Bwd Segment Size', 'Average Packet Size', 'Packet Length Std', 'Bwd Packet Length Max'
]

# Define a function to classify risk
def classify_risk(probabilities):
    risk_levels = {
        'BENIGN': 'Low',
        'DoS slowloris': 'High',
        'DoS Slowhttptest': 'High',
        'DoS Hulk': 'Critical',
        'DoS GoldenEye': 'Critical',
        'Heartbleed': 'Critical'
    }
    
    class_labels = pipeline.classes_
    max_prob_index = probabilities.argmax()
    predicted_label = class_labels[max_prob_index]
    
    risk_level = risk_levels.get(predicted_label, 'Unknown')
    
    prob = probabilities[max_prob_index]
    if prob < 0.25:
        risk_category = 'Low Risk'
    elif prob < 0.50:
        risk_category = 'Medium Risk'
    elif prob < 0.75:
        risk_category = 'High Risk'
    else:
        risk_category = 'Critical Risk'
    
    return predicted_label, prob, risk_level, risk_category

# Function to create the results window
def create_results_window(risk_level, result_text):
    results_window = tk.Toplevel()
    results_window.title("Prediction Result")

    # Set the background color based on the risk level
    if risk_level in ['High', 'Critical']:
        results_window.configure(bg="#f44336")  # Red for High and Critical risk
    else:
        results_window.configure(bg="#4caf50")  # Green for Low and Medium risk

    tk.Label(results_window, text="Prediction Result", font=("Arial", 18, "bold"), bg=results_window.cget("bg"), fg="white").pack(pady=10)
    tk.Label(results_window, text=result_text, font=("Arial", 14), bg=results_window.cget("bg"), fg="white").pack(pady=10)

    # Button to close the window
    tk.Button(results_window, text="Close", command=results_window.destroy, bg="white", fg="black", font=("Arial", 12), padx=10, pady=5).pack(pady=20)

# Define a function to handle the prediction
def predict_risk():
    try:
        # Retrieve and convert user inputs
        try:
            max_packet_length = float(entry_max_packet_length.get())
            avg_bwd_segment_size = float(entry_avg_bwd_segment_size.get())
            average_packet_size = float(entry_average_packet_size.get())
            packet_length_std = float(entry_packet_length_std.get())
            bwd_packet_length_max = float(entry_bwd_packet_length_max.get())
        except ValueError as e:
            # Catch conversion errors and display message
            messagebox.showerror("Invalid Input", "Please enter numeric values only.")
            print(f"Conversion error: {e}")
            return
        
        # Create a DataFrame from the inputs
        user_input = [max_packet_length, avg_bwd_segment_size, average_packet_size, packet_length_std, bwd_packet_length_max]
        sample_df = [user_input]
        
        # Make predictions
        y_proba = pipeline.predict_proba(sample_df)
        y_pred = pipeline.predict(sample_df)
        
        # Classify risk
        prediction, risk_prob, risk_level, risk_category = classify_risk(y_proba[0])
        
        # Prepare the result text
        result_text = (
            f"Prediction: {prediction}\n"
            f"Risk Level: {risk_level}\n"
            f"Risk Category: {risk_category}"
        )
        
        # Display the results in a new window
        create_results_window(risk_level, result_text)
        
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")

# Function to create rounded corners for Entry widgets
def create_rounded_entry(parent, width=250, **kwargs):
    entry_frame = tk.Frame(parent, bg="#f0f0f0", bd=0, relief="flat", padx=8)
    entry_frame.pack(pady=5, anchor=tk.CENTER)
    
    canvas = tk.Canvas(entry_frame, height=30, width=width, bg="white", bd=0, highlightthickness=0)
    canvas.pack(fill=tk.BOTH, expand=True)
    
    entry = tk.Entry(canvas, **kwargs, bd=0, relief="flat", bg="white", width=width//10)
    canvas.create_window((0, 0), window=entry, anchor=tk.NW)
    
    # Add validation for numeric input
    validate_cmd = (entry.register(validate_input), '%P')
    entry.config(validate='key', validatecommand=validate_cmd)

    return entry

def validate_input(value):
    if value == "" or value.isdigit() or (value.count('.') == 1 and value.replace('.', '').isdigit()):
        return True
    return False

# Create the main window
root = tk.Tk()
root.title("Network Traffic Risk Prediction")

# Set background color
root.configure(bg="#e0f7fa")

# Create and place widgets
tk.Label(root, text="Network Traffic Risk Prediction", font=("Arial", 24), bg="#e0f7fa", fg="#00796b").pack(pady=20)

tk.Label(root, text="Enter the following values:", bg="#e0f7fa", fg="#00796b").pack(pady=10)

tk.Label(root, text="Max Packet Length (in bytes):", bg="#e0f7fa", fg="#00796b").pack()
entry_max_packet_length = create_rounded_entry(root, width=350)
entry_max_packet_length.pack(pady=5)

tk.Label(root, text="Average Backward Segment Size (in bytes):", bg="#e0f7fa", fg="#00796b").pack()
entry_avg_bwd_segment_size = create_rounded_entry(root, width=350)
entry_avg_bwd_segment_size.pack(pady=5)

tk.Label(root, text="Average Packet Size (in bytes):", bg="#e0f7fa", fg="#00796b").pack()
entry_average_packet_size = create_rounded_entry(root, width=350)
entry_average_packet_size.pack(pady=5)

tk.Label(root, text="Packet Length Standard Deviation (in bytes):", bg="#e0f7fa", fg="#00796b").pack()
entry_packet_length_std = create_rounded_entry(root, width=350)
entry_packet_length_std.pack(pady=5)

tk.Label(root, text="Max Backward Packet Length (in bytes):", bg="#e0f7fa", fg="#00796b").pack()
entry_bwd_packet_length_max = create_rounded_entry(root, width=350)
entry_bwd_packet_length_max.pack(pady=5)

tk.Button(root, text="Predict Risk", command=predict_risk, bg="#00796b", fg="white", font=("Arial", 14), padx=20, pady=10, relief="flat").pack(pady=20)

# Start the main loop
root.mainloop()
