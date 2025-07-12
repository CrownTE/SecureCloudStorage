import React, { useState, useEffect } from "react";
import axios from "axios";

const FileList = () => {
    const [files, setFiles] = useState([]);

    useEffect(() => {
        fetchFiles();
    }, []);

    const fetchFiles = async () => {
        try {
            const response = await axios.get("http://13.60.220.188:5000/files");
            setFiles(response.data.files);
        } catch (error) {
            console.error("Error fetching files:", error);
        }
    };

    const handleDownload = async (filename) => {
        try {
            const response = await axios.get(`http://13.60.220.188:5000/download/${filename}`, {
                responseType: "blob",
            });

            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement("a");
            link.href = url;
            link.setAttribute("download", filename.replace("encrypted-", ""));
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } catch (error) {
            console.error("Error downloading file:", error);
        }
    };

    return (
        <div style={{ textAlign: "center", marginTop: "20px" }}>
            <h2>Uploaded Files</h2>
            <ul>
                {files.length > 0 ? (
                    files.map((file, index) => (
                        <li key={index}>
                            {file}
                            <button onClick={() => handleDownload(file)} style={{ marginLeft: "10px" }}>
                                Download & Decrypt
                            </button>
                        </li>
                    ))
                ) : (
                    <p>No files uploaded yet.</p>
                )}
            </ul>
        </div>
    );
};

export default FileList;
