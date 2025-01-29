from flask import Flask, request, jsonify
import numpy as np
from urllib.parse import urlparse
import joblib
import os
import sys


# Get the path to the bundled xg_phishing.pkl file, depending on if it's running as a script or an exe
if getattr(sys, 'frozen', False):  # If running as a bundled executable
    model_path = os.path.join(sys._MEIPASS, 'xg_phishing.pkl')
else:  # If running as a script
    model_path = 'xg_phishing.pkl'
model = joblib.load(model_path)

# Initialize Flask app
app = Flask(__name__)

# Define feature extraction logic
def extract_features(url):
    features = {}

    # Parse the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path

    # Feature extraction logic
    features['google_index'] = 1 if "google.com" in url else 0
    features['nb_qm'] = url.count('?')
    features['nb_www'] = url.count('www')
    features['ratio_digits_host'] = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
    features['suspecious_tld'] = 1 if domain.endswith(('.tk', '.ml', '.ga', '.cf', '.gq')) else 0
    features['phish_hints'] = 1 if "phish" in url or "secure" in url else 0
    features['nb_colon'] = url.count(':')
    features['domain_in_brand'] = 1 if "brand" in domain else 0
    features['nb_space'] = url.count(' ')
    features['nb_hyphens'] = url.count('-')
    features['shortening_service'] = 1 if "bit.ly" in url or "tinyurl.com" in url else 0
    features['nb_underscore'] = url.count('_')
    features['longest_word_path'] = max(len(word) for word in path.split('/')) if path else 0
    features['ip'] = 1 if any(char.isdigit() for char in domain.split('.')) else 0
    features['nb_eq'] = url.count('=')
    features['nb_percent'] = url.count('%')
    features['length_words_raw'] = sum(len(word) for word in url.split('/')) / len(url.split('/')) if url.split('/') else 0
    features['nb_slash'] = url.count('/')
    features['longest_words_raw'] = max(len(word) for word in url.split('/')) if url.split('/') else 0
    features['nb_dots'] = url.count('.')
    features['shortest_word_host'] = min(len(word) for word in domain.split('.')) if domain.split('.') else 0
    features['length_hostname'] = len(domain)
    features['nb_com'] = url.count('com')
    features['shortest_word_path'] = min(len(word) for word in path.split('/')) if path.split('/') else 0
    features['char_repeat'] = max(url.count(char) for char in set(url))
    features['tld_in_path'] = 1 if any(tld in path for tld in ['.com', '.net', '.org']) else 0
    features['length_url'] = len(url)
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if url else 0
    features['prefix_suffix'] = 1 if '-' in domain else 0
    features['nb_and'] = url.count('&')
    features['shortest_words_raw'] = min(len(word) for word in url.split('/')) if url.split('/') else 0
    features['https_token'] = 1 if 'https' in domain else 0
    features['avg_words_raw'] = np.mean([len(word) for word in url.split('/')]) if url.split('/') else 0
    features['avg_word_path'] = np.mean([len(word) for word in path.split('/')]) if path.split('/') else 0
    features['avg_word_host'] = np.mean([len(word) for word in domain.split('.')]) if domain.split('.') else 0
    features['longest_word_host'] = max(len(word) for word in domain.split('.')) if domain.split('.') else 0

    # Return features as an array in the same order as the model's input
    return np.array([features[feature] for feature in features.keys()])

# Route to handle POST request for URL prediction
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url')
        
        # Extract features from the provided URL
        features = extract_features(url).reshape(1, -1)
        
        # Get prediction and probabilities
        prediction = model.predict(features)
        prediction_probabilities = model.predict_proba(features)

        # Convert numpy types to native Python types
        phishing_prob = float(prediction_probabilities[0][0])
        safe_prob = float(prediction_probabilities[0][1])

        # Print URL and probabilities to the console
        print(f"URL: {url}")
        print(f"Phishing Probability: {phishing_prob}")
        print(f"Safe Probability: {safe_prob}")

        # Determine phishing status
        if phishing_prob > safe_prob:  # Phishing
            return jsonify({
                "url": url,
                "message": "Warning: This website is classified as phishing.",
                "phishing_probability": phishing_prob,
                "prediction": 1,
                "safe_probability": safe_prob
            })
        else:  # Safe
            return jsonify({
                "url": url,
                "message": "Safe: This website is classified as legitimate.",
                "phishing_probability": phishing_prob,
                "prediction": 0,
                "safe_probability": safe_prob
            })
    except Exception as e:
        return jsonify({"error": str(e)})



if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
