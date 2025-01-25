import subprocess
import time

def run_flask_app():
    # Run the Flask app executable
    print("Starting Flask app...")
    subprocess.Popen(["./dist/app"])

def run_native_host():
    # Run the Native Host executable
    print("Starting Native Host...")
    subprocess.Popen(["./dist/native_host"])

if __name__ == "__main__":
    # Run both executables in parallel
    run_flask_app()
    run_native_host()

    # Keep the main Python script running to keep the subprocesses alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Terminating processes...")
