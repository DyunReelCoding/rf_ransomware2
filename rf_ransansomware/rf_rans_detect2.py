import numpy as np
import joblib  
import re
import pefile
import os

# Get the directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(script_dir, "rf_ransomware.pkl")

# Load the model using the absolute path
model = joblib.load(model_path)

# Feature extraction functions for each feature
def get_dll_characteristics(filepath):
    pe = pefile.PE(filepath)
    return pe.OPTIONAL_HEADER.DllCharacteristics

def get_major_linker_version(filepath):
    pe = pefile.PE(filepath)
    return pe.OPTIONAL_HEADER.MajorLinkerVersion

def get_debug_rva(filepath):
    pe = pefile.PE(filepath)
    if hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
        return pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress  # Debug directory RVA
    return 0

def get_major_os_version(filepath):
    pe = pefile.PE(filepath)
    return pe.OPTIONAL_HEADER.MajorOperatingSystemVersion

def get_debug_size(filepath):
    pe = pefile.PE(filepath)
    if hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
        return pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size  # Debug directory size
    return 0

def get_resource_size(filepath):
    pe = pefile.PE(filepath)
    return pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size  # Resource directory size

def get_size_of_stack_reserve(filepath):
    pe = pefile.PE(filepath)
    return pe.OPTIONAL_HEADER.SizeOfStackReserve

def get_machine(filepath):
    pe = pefile.PE(filepath)
    return pe.FILE_HEADER.Machine

def get_number_of_sections(filepath):
    pe = pefile.PE(filepath)
    return pe.FILE_HEADER.NumberOfSections

def get_iat_vra(filepath):
    pe = pefile.PE(filepath)
    return pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress  # IAT address

def get_major_image_version(filepath):
    pe = pefile.PE(filepath)
    return pe.OPTIONAL_HEADER.MajorImageVersion

def get_export_size(filepath):
    pe = pefile.PE(filepath)
    return pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size  # Export table size

def get_minor_linker_version(filepath):
    pe = pefile.PE(filepath)
    return pe.OPTIONAL_HEADER.MinorLinkerVersion

def get_export_rva(filepath):
    pe = pefile.PE(filepath)
    return pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress  # Export table RVA

def detect_bitcoin_addresses(filepath):
    with open(filepath, "rb") as file:
        content = file.read().decode("utf-8", errors="ignore")
        return len(re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", content))

# Function to extract all necessary features from a file
def extract_features_from_file(filepath):
    features = [
        get_dll_characteristics(filepath),
        get_major_linker_version(filepath),
        get_debug_rva(filepath),
        get_major_os_version(filepath),
        get_debug_size(filepath),
        get_resource_size(filepath),
        get_size_of_stack_reserve(filepath),
        get_machine(filepath),
        get_number_of_sections(filepath),
        get_iat_vra(filepath),
        get_major_image_version(filepath),
        get_export_size(filepath),
        get_minor_linker_version(filepath),
        get_export_rva(filepath),
        detect_bitcoin_addresses(filepath),
    ]
    print("Extracted features:", features)  # Print the extracted features
    return np.array(features).reshape(1, -1)

# Function to classify a file as ransomware or safe
def detect_ransomware_from_file(filepath):
    if not os.path.isfile(filepath):
        print(f"File not found: {filepath}")
        return

    features = extract_features_from_file(filepath)
    prediction = model.predict(features)
    prediction_probabilities = model.predict_proba(features)

    print(f"Prediction: {prediction[0]} (1: ransomware, 0: safe)")

    print(f"Prediction Probabilities: {prediction_probabilities}")

    # Compare the two probabilities
    if prediction_probabilities[0][0] > prediction_probabilities[0][1]:  # Class 1: ransomware
        print("Warning: This file is classified as ransomware.")
    else:  # Class 0: safe
        print("Safe: This file is classified as safe.")


# Path to the executable to test
file_path = input("Enter the full path to the executable to analyze: ")

# Run the ransomware detection on the executable
print("Analyzing the file for ransomware...")
detect_ransomware_from_file(file_path)
