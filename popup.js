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