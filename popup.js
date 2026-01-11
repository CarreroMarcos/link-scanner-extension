chrome.storage.local.get("vtApiKey", (data) => {
    if (data.vtApiKey) {
        document.getElementById("apiKeySection").style.display = "none";
    }
});

chrome.storage.session.get("lastResult", (data) => {
    const resultDiv = document.getElementById("result");

    if (!data.lastResult) {
        resultDiv.textContent = "No scan performed yet.";
        return;
    }

    const res = data.lastResult;

    resultDiv.textContent = res.status.toUpperCase();
    resultDiv.className = res.status;
});

function isValidVirusTotalApiKey(key) {
    if (key.length !== 64) return false;
    const hexRegex = /^[a-fA-F0-9]+$/;
    return hexRegex.test(key);
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

async function scanWithVirusTotal(url, apiKey) {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 5000);

    const res = await fetch(`https://www.virustotal.com/api/v3/urls`, {
        method: "POST",
        headers: {
            "x-apikey": apiKey,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeURIComponent(url)}`,
        signal: controller.signal,
    });
    if (res.status === 429) return gray("RATE_LIMITED");
    if (!res.ok) return gray("VT_API_ERROR");

    return { status: "green", scanned_url: url };
}