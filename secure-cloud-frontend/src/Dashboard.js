import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getToken, removeToken } from './Auth';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const Dashboard = () => {
  const [file, setFile] = useState(null);
  const [files, setFiles] = useState([]);
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    fetchFiles();
  }, []);

  const fetchFiles = async () => {
    try {
      setLoading(true);
      const response = await fetch("http://13.60.220.188:5000/files", {
        headers: { Authorization: `Bearer ${getToken()}` }
      });
      const data = await response.json();
      setFiles(response.ok ? data.files || [] : []);
    } catch (err) {
      console.error(err);
      setFiles([]);
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleUpload = async () => {
    if (!file) return toast.error("Please select a file to upload.");

    const formData = new FormData();
    formData.append("file", file);

    try {
      setLoading(true);
      const response = await fetch("http://13.60.220.188:5000/upload", {
        method: "POST",
        headers: { Authorization: `Bearer ${getToken()}` },
        body: formData
      });
      const data = await response.json();
      if (response.ok) {
        toast.success("File uploaded successfully!");
        setMessage(data.message);
        fetchFiles();
      } else {
        toast.error("Upload failed!");
        setMessage("Error uploading file.");
      }
    } catch (err) {
      console.error(err);
      toast.error("Server error during upload.");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (filename) => {
    const token = getToken();
    if (!token) return alert("You must be logged in to download files.");

    try {
      const response = await fetch(`http://13.60.220.188:5000/download/${filename}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) throw new Error("Download failed.");

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename.replace("encrypted-", "");
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Download error:", error);
      alert("Error occurred during download.");
    }
  };

  const handleLogout = () => {
    removeToken();
    navigate("/");
  };

  return (
    <div style={{ padding: '30px', fontFamily: 'Arial' }}>
      <div style={{ maxWidth: '800px', margin: '0 auto', border: '1px solid #ccc', padding: '30px', borderRadius: '8px' }}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h1 style={{ fontSize: '24px', fontWeight: 'bold' }}>Dashboard</h1>
          <button onClick={handleLogout}style={{
            backgroundColor: '#EF4444',
            color: 'white',
            padding: '8px 16px',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
            }}
            >Logout</button>
        </div>

        {/* File input and Upload */}
        <div style={{ marginTop: '40px' }}>
          <input
            type="file"
            onChange={handleFileChange}
            style={{
              marginBottom: '10px',
              padding: '6px',
              border: '1px solid #ccc',
              borderRadius: '4px',
              display: 'block',
              width: '100%'
            }}
          />
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button
              onClick={handleUpload}
              style={{
                backgroundColor: '#4F46E5',
                color: 'white',
                padding: '8px 16px',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Upload
            </button>
          </div>
        </div>

        {/* Loading */}
        {loading && (
          <div style={{ textAlign: 'center', margin: '20px 0' }}>
            <p>Loading...</p>
          </div>
        )}

        {/* Message */}
        {message && (
          <div style={{ color: 'green', marginTop: '20px', fontWeight: '500' }}>{message}</div>
        )}

        {/* File List */}
        <h2 style={{ fontSize: '18px', fontWeight: '600', marginTop: '30px' }}>Uploaded Files:</h2>
        {Array.isArray(files) && files.length > 0 ? (
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {files.map((file) => (
              <li key={file} style={{
                marginTop: '10px',
                padding: '10px',
                border: '1px solid #ddd',
                borderRadius: '6px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <span>{file}</span>
                <button
                  onClick={() => handleDownload(file)}
                  style={{
                    backgroundColor: '#3B82F6',
                    color: 'white',
                    border: 'none',
                    padding: '6px 12px',
                    borderRadius: '4px',
                    cursor: 'pointer'
                  }}
                >
                  Download
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p style={{ color: '#888', marginTop: '10px' }}>No files uploaded yet.</p>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
