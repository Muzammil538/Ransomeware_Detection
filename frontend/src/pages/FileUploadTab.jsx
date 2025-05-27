import { useDropzone } from "react-dropzone";
import axios from "axios";
import { useState } from "react";

function FileUploadTab() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const onDrop = async (files) => {
    setResult(null);
    setLoading(true);
    const formData = new FormData();
    formData.append("file", files[0]);
    try {
      const res = await axios.post("http://localhost:5000/scan/file", formData);
      setResult(res.data);
    } catch (err) {
      setResult({ error: "Scan failed. Please try again." });
    }
    setLoading(false);
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    accept: {
    'image/*': ['.png', '.jpg', '.jpeg', '.gif'],
    'application/pdf': ['.pdf'],
    'text/plain': ['.txt'],
    // ADD THESE LINES FOR DEMO PURPOSES:
    'application/x-msdownload': ['.exe', '.com'], // Standard MIME type for executables
    'application/octet-stream': ['.bin'] // Generic binary file
    },
  });

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-blue-900 flex flex-col">
      <main className="flex flex-1 flex-col items-center justify-center px-4">
        <div className="bg-gray-800 bg-opacity-90 rounded-xl shadow-lg p-8 w-full max-w-xl flex flex-col items-center">
          <h2 className="text-3xl font-bold text-white mb-4">
            Scan a File for Ransomware
          </h2>
          <div
            {...getRootProps()}
            className={`w-full flex flex-col items-center justify-center border-2 border-dashed rounded-lg px-6 py-12 mb-4 cursor-pointer transition ${
              isDragActive
                ? "border-blue-400 bg-gray-700"
                : "border-blue-700 bg-gray-900"
            }`}
          >
            <input {...getInputProps()} />
            <p className="text-blue-100 text-lg">
              {isDragActive
                ? "Drop the file here..."
                : "Drag & drop a file here, or click to browse"}
            </p>
          </div>
          {loading && (
            <div className="text-blue-300 font-semibold mt-2">Scanning...</div>
          )}
          {result && (
            <div className="mt-6 w-full text-center">
              {result.error ? (
                <div className="text-red-400 font-semibold">{result.error}</div>
              ) : (
                <div
                  className={`text-2xl font-bold`}
                >
                  {
                    // First, check for URL-specific predictions
                    result.result.prediction === "benign" ? (
                      <span style={{ color: "green" }}>✅ SAFE</span>
                    ) :  
                    result.result.prediction === "malicious" ? (
                      <span style={{ color: "red", fontWeight: "bold" }}>
                        🚨 MALICIOUS <br />File : {result.filename}
                      </span>
                    ) : result.result.prediction === "highly_suspicious" ? (
                      <span style={{ color: "darkred" }}>
                        ⚠️ HIGHLY SUSPICIOUS <br />File : {result.filename}
                      </span>
                    ) : result.result.prediction === "suspicious" ? (
                      <span style={{ color: "orange" }}>❓ SUSPICIOUS <br />File : {result.filename}</span>
                    ) : result.result.prediction === "potentially_unwanted" ? (
                      <span style={{ color: "goldenrod" }}>
                        Potentially Unwanted
                      </span>
                    ) : result.result.prediction === "safe" ? ( // This "safe" is for files
                      <span style={{ color: "green" }}>✅ SAFE</span>
                    ) : (
                      // Fallback for any unexpected or unhandled predictions
                      <span style={{ color: "gray" }}>🤔 UNKNOWN</span>
                    )
                  }
                </div>
              )}
            </div>
          )}
        </div>
      </main>
      <footer className="w-full py-4 text-center text-blue-200 text-sm bg-transparent mt-auto">
        &copy; {new Date().getFullYear()} RansomwareGuard. All rights reserved.
      </footer>
    </div>
  );
}

export default FileUploadTab;
