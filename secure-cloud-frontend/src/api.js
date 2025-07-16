import axios from 'axios';

// Dynamic API base URL based on environment
const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? 'https://secure-cloud-storage-mszj.onrender.com'
  : 'http://localhost:5000';

const API = axios.create({
  baseURL: API_BASE_URL,
});

// Add request interceptor to include auth token
API.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Auth functions
export const register = (username, password) => {
  return API.post('/register', { username, password });
};

export const login = (username, password) => {
  return API.post('/login', { username, password });
};

// File functions
export const uploadFile = (file) => {
  const formData = new FormData();
  formData.append('file', file);
  return API.post('/upload', formData);
};

export const downloadFile = (filename) => {
  return API.get(`/download/${filename}`, { responseType: 'blob' });
};

export const listFiles = () => {
  return API.get('/files');  // Changed from '/list-files' to match your backend
};

export default API;
