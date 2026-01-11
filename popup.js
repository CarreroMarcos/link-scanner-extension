chrome.storage.local.get("vtApiKey", (data) => {
    if (data.vtApiKey) {
        document.getElementById("apiKeySection").style.display = "none";
    }
});

function isValidVirusTotalApiKey(key) {
    return /^[a-f0-9]{64}$/i.test(key);
}

document.getElementById("saveKey").addEventListener("click", () => {
    const key = document.getElementById("apiKey").value;
    
    if (!key) {
        alert("Please enter an API Key.");
        return;
    }

    if (!isValidVirusTotalApiKey(key)) {
        alert("Invalid API Key format.");
        return;
    }

    chrome.storage.local.set({ vtApiKey: key }, () => {
        if (chrome.runtime.lastError) {
            alert("Error saving API Key: " + chrome.runtime.lastError.message);
        } else {
            alert("API Key saved successfully!");
            document.getElementById("apiKeySection").style.display = "none";
        }
    });

});

document.addEventListener("DOMContentLoaded", () => {
    const statusElement = document.getElementById("status");
    const messageElement = document.getElementById("message");
    const refreshBtn = document.getElementById("refreshBtn");
    const statusCircle = document.getElementById("statusCircle");
    const scannedUrlElement = document.getElementById("scannedUrl");
    const cleanedUrlElement = document.getElementById("cleanedUrl");

    // Add null checks
    if (!statusElement || !messageElement || !refreshBtn || !statusCircle || !scannedUrlElement || !cleanedUrlElement) {
        console.error("Required elements not found in the DOM.");
        return;
    }

    function loadScanResult() {
        chrome.storage.session.get("lastScanResult", (data) => {
            if (chrome.runtime.lastError) {
                console.error("Error retrieving scan result:", chrome.runtime.lastError);
                if (statusElement) statusElement.textContent = "Error";
                if (messageElement) messageElement.textContent = "Failed to load scan result.";
                return;
            }

            const result = data.lastScanResult;
            if (result) {
                let displayStatus = result.status.toUpperCase();
                if (displayStatus === "GRAY") displayStatus = "UNVERIFIABLE";
                if (statusElement) statusElement.textContent = displayStatus;
                if (scannedUrlElement) scannedUrlElement.textContent = result.scanned_url ? `Scanned URL: ${result.scanned_url}` : "";
                if (cleanedUrlElement) {
                    cleanedUrlElement.href = result.cleaned_url || "";
                    cleanedUrlElement.textContent = result.cleaned_url ? `Cleaned URL: ${result.cleaned_url}` : "";
                }
                if (messageElement) messageElement.textContent = result.message || "No message available.";
                if (statusCircle) {
                    const status = result.status.toUpperCase();
                    if (status === "SAFE") {
                        statusCircle.className = "status-circle valid";
                    } else if (status === "MALICIOUS") {
                        statusCircle.className = "status-circle danger";
                    } else {
                        statusCircle.className = "status-circle invalid";
                    }
                }
            } else {
                if (statusElement) statusElement.textContent = "No scan performed";
                if (scannedUrlElement) scannedUrlElement.textContent = "";
                if (cleanedUrlElement) {
                    cleanedUrlElement.href = "";
                    cleanedUrlElement.textContent = "";
                }
                if (messageElement) messageElement.textContent = "Right-click on a link and select 'Scan Link with VirusTotal' to scan it.";
                if (statusCircle) statusCircle.className = "status-circle invalid";
            }
        });
    }

    loadScanResult();

    refreshBtn.addEventListener("click", () => {
        loadScanResult();
    });
});

