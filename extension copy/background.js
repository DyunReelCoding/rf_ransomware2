const serverUrl = "http://localhost:5000/detect_ransomware";
let currentRansomwareFile = null;

// Extensions to monitor
const monitoredExtensions = [".exe", ".bin", ".dll", ".scr", ".pif"];

// Declare downloadDir at the top to ensure proper scoping
let downloadDir = "";

// Function to determine the download directory based on platform
function determineDownloadDir(callback) {
  const platform = navigator.userAgent.includes("Win") ? "windows" : "linux";
  
  // Fetch the username dynamically from the native host
  getUsernameFromNativeHost((username) => {
    let dir;
    if (platform === "windows") {
      dir = `C:\\Users\\${username}\\Downloads`;
    } else {
      dir = `/home/${username}/Downloads`;
    }
    downloadDir = dir;  // Set the global downloadDir
    callback();  // Call the callback once downloadDir is set
  });
}

// Function to get the username dynamically via native messaging
function getUsernameFromNativeHost(callback) {
  const port = chrome.runtime.connectNative("com.native_username_retriever");
  
  port.onMessage.addListener((message) => {
    if (message.username) {
      callback(message.username);  // Return the username to the callback
    } else {
      console.error("Failed to retrieve username from native host.");
      callback("unknown_user");  // Fallback to a default username
    }
  });

  port.onDisconnect.addListener(() => {
    if (chrome.runtime.lastError) {
      console.error("Native host error:", chrome.runtime.lastError.message);
    }
  });
}

// Check if the server is running
function checkServerStatus() {
  fetch(serverUrl, { method: "HEAD" })
    .then(() => {
      console.log("Server is running.");
    })
    .catch(() => {
      console.log("Server is not running. Attempting to start it...");
      startNativeHost();
    });
}

// Start the server using the native messaging host
function startNativeHost() {
  const port = chrome.runtime.connectNative("com.server_starter");
  port.onDisconnect.addListener(() => {
    if (chrome.runtime.lastError) {
      console.error("Failed to start server via native host:", chrome.runtime.lastError.message);
    } else {
      console.log("Native host disconnected.");
    }
  });
  port.onMessage.addListener((message) => {
    console.log("Message from native host:", message);
  });

  // Send a message to start the server
  port.postMessage({ action: "start_server" });
}

// Monitor downloads
chrome.downloads.onChanged.addListener((downloadDelta) => {
  if (downloadDelta.state && downloadDelta.state.current === "complete") {
    chrome.downloads.search({ id: downloadDelta.id }, (results) => {
      if (results && results[0]) {
        const filePath = results[0].filename;

        // Check if the file is in the specified directory and matches monitored extensions
        if (filePath.startsWith(downloadDir) && matchesMonitoredExtensions(filePath)) {
          console.log(`New potentially executable file detected: ${filePath}`);
          processFile(filePath, results[0].id);
        }
      }
    });
  }
});

// Function to check if a file matches monitored extensions
function matchesMonitoredExtensions(filePath) {
  return monitoredExtensions.some((ext) => filePath.endsWith(ext));
}

// Function to send the file path to the Flask server
function processFile(filePath, downloadId) {
  fetch(serverUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ file_path: filePath }),
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`Server responded with status ${response.status}`);
      }
      return response.json();
    })
    .then((result) => {
      if (result.file_status === "ransomware") {
        console.warn(`Warning: The file ${filePath} is classified as ransomware.`);
        currentRansomwareFile = filePath;

        // Open the popup
        chrome.windows.create({
          url: "popup.html",
          type: "popup",
          width: 400,
          height: 300,
        });
      } else {
        console.log(`The file ${filePath} is safe.`);
      }
    })
    .catch((error) => {
      console.error("Error communicating with the Flask server:", error);
    });
}

// Function to delete a file
function deleteFile(filePath) {
  chrome.downloads.search({ filename: filePath }, (results) => {
    if (results && results.length > 0) {
      const downloadId = results[0].id;

      chrome.downloads.removeFile(downloadId, (success) => {
        if (chrome.runtime.lastError || !success) {
          console.error(`Failed to delete file: ${filePath}`, chrome.runtime.lastError);
        } else {
          console.log(`File deleted: ${filePath}`);
        }
      });
    } else {
      console.error(`File not found in downloads: ${filePath}`);
    }
  });
}

// Handle messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getFilePath") {
    sendResponse({ filePath: currentRansomwareFile });
  } else if (message.action === "deleteFile") {
    deleteFile(message.filePath);
    sendResponse({ success: true });
  } else if (message.action === "keepFile") {
    console.log("User chose to keep the file.");
    sendResponse({ success: true });
  }
});

// Check server status on extension load
checkServerStatus();

// Set downloadDir after it has been determined
determineDownloadDir(() => {
  console.log("Download directory set:", downloadDir);
  // Now that the download directory is set, you can perform other tasks that depend on it.
});
