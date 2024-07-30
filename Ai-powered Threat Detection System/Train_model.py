import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
import joblib
import time  # Import time for timing the training duration

file_path = r"C:\Users\Luis_L\OneDrive - Dell Technologies\Documents\Dell Intern\Project\Ai-powered Threat Detection System\Dataset.csv"

def load_data(file_path):
    """
    Load the dataset from a CSV file.
    """
    data = pd.read_csv(file_path)
    return data

def preprocess_data(data):
    """
    Preprocess the dataset.
    """
    # Print column names for debugging
    print("Columns in the dataset:", data.columns)
    
    # Drop rows with missing labels
    data = data.dropna(subset=[' Label'])
    
    # Replace infinite values with NaN
    data.replace([float('inf'), -float('inf')], pd.NA, inplace=True)
    
    # Drop rows with any NaN values
    data.dropna(inplace=True)
    
    # Convert columns to numeric, if necessary
    data = data.apply(pd.to_numeric, errors='ignore')
    
    # Separate features and labels
    X = data.drop(columns=[' Label'])
    y = data[' Label']
    
    return X, y

def build_model():
    """
    Build and return a Random Forest Classifier model.
    """
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    pipeline = make_pipeline(StandardScaler(), model)
    return pipeline

def train_model(X_train, y_train, model):
    """
    Train the model with the training data.
    """
    print("Training the model...")
    start_time = time.time()  # Start timing
    model.fit(X_train, y_train)
    end_time = time.time()  # End timing
    
    print("Model training completed.")
    print(f"Training time: {end_time - start_time:.2f} seconds")  # Print training duration

def evaluate_model(X_test, y_test, model):
    """
    Evaluate the model and print performance metrics.
    """
    y_pred = model.predict(X_test)
    
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

def save_model(model, filename):
    """
    Save the trained model to a file.
    """
    joblib.dump(model, filename)
    print(f"Model saved to {filename}")

def select_top_features(X, y, top_n=5):
    """
    Select the top N features based on feature importance from a RandomForest model.
    """
    print("Selecting top features...")
    
    # Train the model on the entire dataset
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    # Get feature importances
    feature_importances = model.feature_importances_
    
    # Create a DataFrame for feature importances
    feature_importances_df = pd.DataFrame({
        'Feature': X.columns,
        'Importance': feature_importances
    }).sort_values(by='Importance', ascending=False)
    
    # Print feature importances for debugging
    print("Feature importances:")
    print(feature_importances_df)
    
    # Select top N features
    top_features = feature_importances_df.head(top_n)['Feature'].tolist()
    
    return top_features

def main():
    print("Loading data...")
    data = load_data(file_path)
    
    print("Preprocessing data...")
    X, y = preprocess_data(data)
    
    print("Selecting top 5 features...")
    top_features = select_top_features(X, y, top_n=5)
    print(f"Top 5 features: {top_features}")
    
    # Update features to use only the top 5 features
    X = X[top_features]
    
    print("Splitting data into training and testing sets...")
    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    print("Building model...")
    # Build and train the model
    model = build_model()
    
    print("Starting model training...")
    train_model(X_train, y_train, model)
    
    print("Evaluating model...")
    # Evaluate the model
    evaluate_model(X_test, y_test, model)
    
    print("Saving model...")
    # Save the model
    save_model(model, 'network_traffic_model.pkl')

if __name__ == "__main__":
    main()
