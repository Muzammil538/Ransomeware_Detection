import React, { useState } from "react";
import axios from "axios";
import { Link } from "react-router";

function UrlScanTab() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setResult(null);
    setLoading(true);
    try {
      const res = await axios.post("http://localhost:5000/scan/url", { url });
      setResult(res.data);
    } catch (err) {
      setResult({ error: "Scan failed. Please try again. " });
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-blue-900 flex flex-col">

      {/* Main Content */}
      <main className="flex flex-1 flex-col items-center justify-center px-4">
        <div className="bg-gray-800 bg-opacity-90 rounded-xl shadow-lg p-8 w-full max-w-xl flex flex-col items-center">
          <h2 className="text-3xl font-bold text-white mb-4">Scan a URL for Ransomware</h2>
          <form onSubmit={handleSubmit} className="w-full flex flex-col items-center">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan"
              className="w-full px-4 py-3 rounded-lg mb-4 bg-gray-900 text-white border border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-400"
              required
            />
            <button
              type="submit"
              className="w-full py-3 rounded-full bg-gradient-to-r from-blue-500 to-blue-700 text-white font-bold text-lg shadow hover:from-blue-600 hover:to-blue-800 transition mb-2"
              disabled={loading}
            >
              {loading ? "Scanning..." : "Scan URL"}
            </button>
          </form>
          {result && ( // This checks if result is not null
          <div>
              {/*
                  THIS IS THE CRITICAL SECTION
                  How are you interpreting 'result.prediction'?
              */}
              <p>
                  {result.result.prediction === 'safe' ? (
                      <span style={{ color: 'green' }}>Safe</span>
                  ) : (
                      // This is what should be triggered if prediction is 'phishing', 'malware', etc.
                      <span style={{ color: 'red' }}>Prediction :  {result.result.prediction} - Could be Malicious</span>
                  )}
              </p>
              {/* ... potentially display other info like probabilities */}
          </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="w-full py-4 text-center text-blue-200 text-sm bg-transparent mt-auto">
        &copy; {new Date().getFullYear()} RansomwareGuard. All rights reserved.
      </footer>
    </div>
  );
}


export default UrlScanTab;