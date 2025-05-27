from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import hashlib
import re
import urllib.parse
import socket
import whois
import dns.resolver
import tldextract
import magic
# import yara  # Removed due to installation issues
import math
import requests
from datetime import datetime, timedelta
import joblib
import os
import logging
from werkzeug.utils import secure_filename
import tempfile
import binascii
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'exe', 'dll', 'doc', 'docx', 'zip', 'rar', 'com'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create upload directory
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Trusted domains and patterns
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
    'wikipedia.org', 'reddit.com', 'netflix.com', 'instagram.com', 'whatsapp.com',
    'zoom.us', 'dropbox.com', 'adobe.com', 'salesforce.com', 'oracle.com',
    'ibm.com', 'paypal.com', 'ebay.com', 'spotify.com', 'pinterest.com',
    'codepen.io', 'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com'
}

TRUSTED_SUBDOMAINS = {
    'googleapis.com', 'googleusercontent.com', 'gstatic.com', 'googlesyndication.com',
    'facebook.com', 'fbcdn.net', 'amazonaws.com', 'cloudfront.net',
    'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com',
    'apple.com', 'icloud.com', 'cdn.jsdelivr.net', 'unpkg.com'
}

# Suspicious patterns
PHISHING_KEYWORDS = [
    'verify', 'suspended', 'urgent', 'update', 'confirm', 'secure', 'account',
    'login', 'signin', 'bank', 'paypal-', 'amazon-', 'microsoft-', 'apple-',
    'facebook-', 'google-', 'twitter-', 'linkedin-', 'instagram-'
]

MALICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.js', '.jar', '.app',
    '.deb', '.pkg', '.dmg', '.msi', '.run', '.cmd', '.ps1'
}

class URLFeatureExtractor:
    def __init__(self):
        self.tld_extractor = tldextract.TLDExtract()
        
    def extract_features(self, url):
        """Extract comprehensive features from URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            tld_info = self.tld_extractor(url)
            
            features = {}
            
            # Basic URL structure features
            features['url_length'] = len(url)
            features['hostname_length'] = len(parsed.hostname) if parsed.hostname else 0
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query) if parsed.query else 0
            features['fragment_length'] = len(parsed.fragment) if parsed.fragment else 0
            
            # Character-based features
            features['dot_count'] = url.count('.')
            features['hyphen_count'] = url.count('-')
            features['underscore_count'] = url.count('_')
            features['slash_count'] = url.count('/')
            features['question_count'] = url.count('?')
            features['equal_count'] = url.count('=')
            features['ampersand_count'] = url.count('&')
            features['percent_count'] = url.count('%')
            features['digit_count'] = sum(c.isdigit() for c in url)
            
            # Domain trust features
            features['is_trusted_domain'] = self._is_trusted_domain(tld_info)
            features['domain_age_suspicion'] = self._check_domain_age(tld_info.top_domain_under_public_suffix)
            features['has_suspicious_tld'] = self._has_suspicious_tld(tld_info.suffix)
            
            # Phishing detection features
            features['has_ip_address'] = self._has_ip_address(parsed.hostname)
            features['has_suspicious_keywords'] = self._has_suspicious_keywords(url)
            features['url_shortener'] = self._is_url_shortener(tld_info.top_domain_under_public_suffix)
            features['suspicious_port'] = self._has_suspicious_port(parsed.port)
            
            # Entropy and randomness features
            features['hostname_entropy'] = self._calculate_entropy(parsed.hostname or '')
            features['path_entropy'] = self._calculate_entropy(parsed.path)
            features['subdomain_count'] = len(tld_info.subdomain.split('.')) if tld_info.subdomain else 0
            features['hex_chars_ratio'] = self._hex_chars_ratio(url)
            
            # URL encoding features
            features['url_encoded_chars'] = url.count('%')
            features['special_chars_count'] = len(re.findall(r'[!@#$%^&*()_+={}\[\]|\\:";\'<>?,./~`]', url))
            
            # Security indicators
            features['https_scheme'] = 1 if parsed.scheme == 'https' else 0
            features['www_prefix'] = 1 if parsed.hostname and parsed.hostname.startswith('www.') else 0
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from URL {url}: {e}")
            return self._get_default_features()
    
    def _is_trusted_domain(self, tld_info):
        """Check if domain is trusted"""
        domain = tld_info.top_domain_under_public_suffix
        fqdn = tld_info.fqdn
        
        # Check direct domain match
        if domain in TRUSTED_DOMAINS:
            return 1
        
        # Check subdomain patterns
        for trusted in TRUSTED_SUBDOMAINS:
            if fqdn.endswith('.' + trusted) or fqdn == trusted:
                return 1
        
        # Check if it's a subdomain of trusted domain
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or fqdn.endswith('.' + trusted):
                return 1
                
        return 0
    
    def _check_domain_age(self, domain):
        """Check domain age (simplified)"""
        try:
            # This would require actual WHOIS lookup
            # For now, return 0 (not suspicious)
            return 0
        except:
            return 0.5  # Unknown, moderately suspicious
    
    def _has_suspicious_tld(self, tld):
        """Check for suspicious TLDs"""
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.top', '.click'}
        return 1 if tld in suspicious_tlds else 0
    
    def _has_ip_address(self, hostname):
        """Check if hostname is an IP address"""
        if not hostname:
            return 0
        try:
            socket.inet_aton(hostname)
            return 1
        except:
            return 0
    
    def _has_suspicious_keywords(self, url):
        """Check for phishing keywords"""
        url_lower = url.lower()
        for keyword in PHISHING_KEYWORDS:
            if keyword in url_lower:
                return 1
        return 0
    
    def _is_url_shortener(self, domain):
        """Check if domain is a URL shortener"""
        shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link'}
        return 1 if domain in shorteners else 0
    
    def _has_suspicious_port(self, port):
        """Check for suspicious ports"""
        if port is None:
            return 0
        suspicious_ports = {8080, 8443, 3128, 1080, 8888}
        return 1 if port in suspicious_ports else 0
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy"""
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p, 2) for p in prob])
        return entropy
    
    def _hex_chars_ratio(self, url):
        """Calculate ratio of hexadecimal characters"""
        hex_chars = sum(1 for c in url if c in '0123456789abcdefABCDEF')
        return hex_chars / len(url) if url else 0
    
    def _get_default_features(self):
        """Return default features in case of error"""
        return {key: 0 for key in [
            'url_length', 'hostname_length', 'path_length', 'query_length', 'fragment_length',
            'dot_count', 'hyphen_count', 'underscore_count', 'slash_count', 'question_count',
            'equal_count', 'ampersand_count', 'percent_count', 'digit_count', 'is_trusted_domain',
            'domain_age_suspicion', 'has_suspicious_tld', 'has_ip_address', 'has_suspicious_keywords',
            'url_shortener', 'suspicious_port', 'hostname_entropy', 'path_entropy', 'subdomain_count',
            'hex_chars_ratio', 'url_encoded_chars', 'special_chars_count', 'https_scheme', 'www_prefix'
        ]}

class FileAnalyzer:
    def __init__(self):
        try:
            self.magic = magic.Magic(mime=True)
        except:
            # Fallback if python-magic is not properly installed
            self.magic = None
        
        # Predefined malware signatures (hex patterns)
        self.malware_signatures = {
            'eicar': '58354f2150254040505b345c505a58353428505e29377d24454943415221',
            'wannacry': '4d534d4f43532e455845',
            'petya': '504554594120524541444d45',
            'ransomware_marker1': '796f75722066696c65732068617665206265656e20656e637279707465',
            'ransomware_marker2': '7061792074686520726174736f6d',
            'backdoor_marker': '6e65742075736572202f616464',
            'keylogger_marker': '47657441737962634b6579537461'
        }
        
        # Suspicious strings patterns
        self.suspicious_patterns = [
            # Windows API calls commonly used by malware
            b'CreateRemoteThread', b'VirtualAlloc', b'WriteProcessMemory',
            b'RegSetValue', b'ShellExecute', b'WinExec', b'URLDownloadToFile',
            b'GetProcAddress', b'LoadLibrary', b'CreateProcess',
            
            # Ransomware indicators
            b'encrypted', b'decrypt', b'bitcoin', b'ransom', b'payment',
            b'files have been', b'pay the', b'restore your files',
            
            # Network activity
            b'socket', b'connect', b'send', b'recv', b'http',
            b'download', b'upload',
            
            # System manipulation
            b'regedit', b'cmd.exe', b'powershell', b'taskkill',
            b'net user', b'net localgroup'
        ]
        
    def analyze_file(self, file_path):
        """Analyze file for malware indicators"""
        try:
            features = {}
            
            # File metadata
            file_stat = os.stat(file_path)
            features['file_size'] = file_stat.st_size
            features['file_entropy'] = self._calculate_file_entropy(file_path)
            
            # MIME type detection
            if self.magic:
                try:
                    mime_type = self.magic.from_file(file_path)
                except:
                    mime_type = 'application/octet-stream'
            else:
                # Fallback MIME detection
                mime_type = self._detect_mime_fallback(file_path)
                
            features['mime_type'] = mime_type
            features['suspicious_mime'] = self._is_suspicious_mime(mime_type)
            
            # File extension analysis
            _, ext = os.path.splitext(file_path)
            features['suspicious_extension'] = 1 if ext.lower() in MALICIOUS_EXTENSIONS else 0
            
            # Hash analysis
            features['file_hash'] = self._calculate_file_hash(file_path)
            features['known_malware'] = self._check_known_malware_hash(features['file_hash'])
            
            # PE analysis for executables
            if ext.lower() in ['.exe', '.dll', '.scr']:
                pe_features = self._analyze_pe_file(file_path)
                features.update(pe_features)
            
            # Advanced malware detection
            features['malware_signatures'] = self._scan_malware_signatures(file_path)
            features['suspicious_strings'] = self._analyze_strings(file_path)
            features['suspicious_patterns'] = self._scan_suspicious_patterns(file_path)
            
            # Behavioral analysis
            features['network_indicators'] = self._detect_network_behavior(file_path)
            features['persistence_indicators'] = self._detect_persistence_mechanisms(file_path)
            
            return features
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return {'error': str(e)}
    
    def _calculate_file_entropy(self, file_path):
        """Calculate file entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if not data:
                return 0
            
            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            file_len = len(data)
            entropy = 0
            for count in byte_counts:
                if count > 0:
                    p = count / file_len
                    entropy -= p * math.log2(p)
            
            return entropy
        except:
            return 0
    
    def _detect_mime_fallback(self, file_path):
        """Fallback MIME type detection"""
        try:
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            
            mime_map = {
                '.exe': 'application/x-msdownload',
                '.dll': 'application/x-msdownload',
                '.scr': 'application/x-msdownload',
                '.bat': 'application/x-msdos-program',
                '.com': 'application/x-msdos-program',
                '.pdf': 'application/pdf',
                '.doc': 'application/msword',
                '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                '.zip': 'application/zip',
                '.rar': 'application/x-rar-compressed'
            }
            
            return mime_map.get(ext, 'application/octet-stream')
        except:
            return 'application/octet-stream'
    
    def _scan_malware_signatures(self, file_path):
        """Scan for known malware signatures"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Convert to hex string for pattern matching
            hex_content = binascii.hexlify(content).decode('ascii').lower()
            
            detected_signatures = []
            for sig_name, sig_pattern in self.malware_signatures.items():
                if sig_pattern in hex_content:
                    detected_signatures.append(sig_name)
            
            return len(detected_signatures) / len(self.malware_signatures)
        except:
            return 0
    
    def _scan_suspicious_patterns(self, file_path):
        """Scan for suspicious byte patterns"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            suspicious_count = 0
            for pattern in self.suspicious_patterns:
                if pattern in content:
                    suspicious_count += 1
            
            return suspicious_count / len(self.suspicious_patterns)
        except:
            return 0
    
    def _detect_network_behavior(self, file_path):
        """Detect network-related behavior indicators"""
        network_indicators = [
            b'http://', b'https://', b'ftp://', b'tcp://',
            b'socket', b'connect', b'bind', b'listen',
            b'recv', b'send', b'download', b'upload'
        ]
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            found_indicators = sum(1 for indicator in network_indicators if indicator in content)
            return found_indicators / len(network_indicators)
        except:
            return 0
    
    def _detect_persistence_mechanisms(self, file_path):
        """Detect persistence mechanism indicators"""
        persistence_indicators = [
            b'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            b'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            b'\\System32\\drivers\\',
            b'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
            b'schtasks', b'at.exe', b'crontab'
        ]
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            found_indicators = sum(1 for indicator in persistence_indicators if indicator in content)
            return found_indicators / len(persistence_indicators)
        except:
            return 0
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except:
            return ""
    
    def _check_known_malware_hash(self, file_hash):
        """Check against known malware hashes (simplified)"""
        # In production, this would check against threat intelligence feeds
        # For now, return 0 (not known malware)
        return 0
    
    def _analyze_pe_file(self, file_path):
      """Analyze PE file structure"""
      pe_features = {
          'has_suspicious_imports': 0,
          'packed_executable': 0,
          'unusual_sections': 0
      }
      
      # This would require pefile library for proper PE analysis
      # For now, return basic features
    def _is_suspicious_mime(self, mime_type):
      """Check if MIME type is suspicious"""
      suspicious_mimes = [
          'application/x-executable',
          'application/x-msdos-program',
          'application/x-msdownload',
          'application/octet-stream'
      ]
      return 1 if mime_type in suspicious_mimes else 0
    def _analyze_strings(self,file_path):
      """Analyze suspicious strings in file"""
      suspicious_strings = [
          'CreateRemoteThread', 'VirtualAlloc', 'WriteProcessMemory',
          'RegSetValue', 'ShellExecute', 'WinExec', 'URLDownloadToFile'
      ]
      
      try:
          with open(file_path, 'rb') as f:
              content = f.read().decode('utf-8', errors='ignore')
          
          found_strings = sum(1 for s in suspicious_strings if s in content)
          return min(found_strings / len(suspicious_strings), 1.0)
      except:
          return 0

class MalwareDetector:
    def __init__(self):
        self.url_extractor = URLFeatureExtractor()
        self.file_analyzer = FileAnalyzer()
        self.url_model = None
        self.file_model = None
        self.url_vectorizer = None
        self.scaler = StandardScaler()
        
    def train_url_model(self, training_data=None):
        """Train URL classification model"""
        if training_data is None:
            # Create sample training data
            training_data = self._generate_sample_url_data()
        
        # Extract features
        X_features = []
        X_text = []
        y = []
        
        for url, label in training_data:
            features = self.url_extractor.extract_features(url)
            X_features.append(list(features.values()))
            X_text.append(url)
            y.append(label)
        
        # Convert to arrays
        X_features = np.array(X_features)
        y = np.array(y)
        
        # Text vectorization
        self.url_vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3))
        X_text_vec = self.url_vectorizer.fit_transform(X_text)
        
        # Combine features
        X_combined = np.hstack([X_features, X_text_vec.toarray()])
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X_combined)
        
        # Train model with enhanced parameters
        self.url_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42
        )
        
        self.url_model.fit(X_scaled, y)
        logger.info("URL model trained successfully")
        
    def predict_url(self, url):
        """Predict if URL is malicious"""
        try:
            if self.url_model is None:
                self.train_url_model()
            
            # Extract features
            features = self.url_extractor.extract_features(url)
            X_features = np.array([list(features.values())])
            
            # Text vectorization
            X_text_vec = self.url_vectorizer.transform([url])
            
            # Combine features
            X_combined = np.hstack([X_features, X_text_vec.toarray()])
            X_scaled = self.scaler.transform(X_combined)
            
            # Predict
            prediction_proba = self.url_model.predict_proba(X_scaled)[0]
            prediction = self.url_model.predict(X_scaled)[0]
            
            # Enhanced confidence calculation with trust boost
            confidence = max(prediction_proba)
            
            # Apply trust domain boost
            if features.get('is_trusted_domain', 0) == 1:
                # Significantly boost confidence for trusted domains towards benign
                if prediction == 0:  # benign
                    confidence = min(confidence * 1.5, 0.99)
                else:  # malicious - reduce confidence significantly
                    confidence = max(confidence * 0.3, 0.1)
                    if confidence < 0.6:  # Override prediction if confidence is low
                        prediction = 0
            
            # Classification with adaptive threshold
            threshold = 0.7
            if confidence < threshold:
                result = "uncertain"
            else:
                result = "malicious" if prediction == 1 else "safe"
            
            return {
                'prediction': result,
                'confidence': float(confidence),
                'details': {
                    'probabilities': {
                        'safe': float(prediction_proba[0]),
                        'malicious': float(prediction_proba[1])
                    },
                    'features': features,
                    'trusted_domain': bool(features.get('is_trusted_domain', 0))
                }
            }
            
        except Exception as e:
            logger.error(f"Error predicting URL {url}: {e}")
            return {'error': str(e)}
    
    def predict_file(self, file_path):
        """Predict if file is malicious"""
        try:
            features = self.file_analyzer.analyze_file(file_path)
            
            if 'error' in features:
                return features
            
            # Enhanced scoring with multiple detection methods
            score = 0
            
            # High entropy indicates possible packing/encryption
            if features.get('file_entropy', 0) > 7.5:
                score += 0.25
            
            # Suspicious MIME type
            if features.get('suspicious_mime', 0):
                score += 0.15
            
            # Suspicious extension
            if features.get('suspicious_extension', 0):
                score += 0.20
            
            # Known malware hash
            if features.get('known_malware', 0):
                score = 1.0
            
            # Malware signatures detected
            signature_score = features.get('malware_signatures', 0)
            if signature_score > 0:
                score += signature_score * 0.8  # High weight for signature matches
            
            # Suspicious strings and patterns
            score += features.get('suspicious_strings', 0) * 0.3
            score += features.get('suspicious_patterns', 0) * 0.25
            
            # Network and persistence indicators
            score += features.get('network_indicators', 0) * 0.2
            score += features.get('persistence_indicators', 0) * 0.3
            
            # File size anomalies
            file_size = features.get('file_size', 0)
            if file_size > 0:
                # Very small executables or very large files can be suspicious
                if file_size < 1024 and features.get('suspicious_extension', 0):  # < 1KB executable
                    score += 0.15
                elif file_size > 100 * 1024 * 1024:  # > 100MB
                    score += 0.10
            
            # Enhanced classification with more granular thresholds
            # if score >= 0.8:
            #     result = "malicious"
            #     confidence = min(score, 0.98)
            # elif score >= 0.6:
            #     result = "highly_suspicious"
            #     confidence = score
            # elif score >= 0.4:
            #     result = "suspicious"
            #     confidence = score
            # elif score >= 0.2:
            #     result = "potentially_unwanted"
            #     confidence = score
            # else:
            #     result = "safe"
            #     confidence = 1 - score
            if score >= 0.35:
                result = "malicious"
                confidence = min(score, 0.9)
            elif score >= 0.24:
                result = "potentially_unwanted"
                confidence = score
            else:
                result = "safe"
                confidence = 1 - score
            
            return {
                'prediction': result,
                'confidence': float(confidence),
                'details': {
                    'file_hash': features.get('file_hash', ''),
                    'file_size': features.get('file_size', 0),
                    'mime_type': features.get('mime_type', ''),
                    'entropy': features.get('file_entropy', 0),
                    'malware_signatures': features.get('malware_signatures', 0),
                    'suspicious_patterns': features.get('suspicious_patterns', 0),
                    'network_indicators': features.get('network_indicators', 0),
                    'persistence_indicators': features.get('persistence_indicators', 0),
                    'total_score': score,
                    'features': features
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return {'error': str(e)}
    
    def _generate_sample_url_data(self):
        """Generate sample training data"""
        # Sample malicious URLs
        malicious_urls = [
            "http://phishing-site.tk/update-account",
            "http://192.168.1.1/malware.exe",
            "http://fake-bank-login.com/secure",
            "http://suspicious-site.ml/verify-paypal",
            "http://malware-host.ga/download.zip",
            "http://fake-amazon.cc/login-update",
            "http://phish-google.tk/signin"
        ]
        
        # Sample benign URLs
        benign_urls = [
            "https://www.google.com/search?q=example",
            "https://github.com/user/repository",
            "https://stackoverflow.com/questions/12345",
            "https://codepen.io/user/pen/abcdef",
            "https://gemini.google.com/app",
            "https://www.youtube.com/watch?v=abc123",
            "https://docs.microsoft.com/en-us/guide",
            "https://aws.amazon.com/ec2/",
            "https://developer.mozilla.org/en-US/docs"
        ]
        
        # Combine and label
        training_data = []
        training_data.extend([(url, 1) for url in malicious_urls])  # 1 = malicious
        training_data.extend([(url, 0) for url in benign_urls])     # 0 = benign
        
        return training_data

# Initialize detector
detector = MalwareDetector()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/scan/url', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        # Validate URL format
        if not re.match(r'^https?://', url):
            url = 'http://' + url
        
        result = detector.predict_url(url)
        
        if 'error' in result:
            return jsonify(result), 500
        
        return jsonify({
            'url': url,
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in analyze_url: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/file', methods=['POST'])
def analyze_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(temp_path)
        
        try:
            result = detector.predict_file(temp_path)
            
            # Clean up temporary file
            os.remove(temp_path)
            
            if 'error' in result:
                return jsonify(result), 500
            
            return jsonify({
                'filename': filename,
                'result': result,
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            # Clean up on error
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e
            
    except Exception as e:
        logger.error(f"Error in analyze_file: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze():
    try:
        data = request.get_json()
        if not data or 'urls' not in data:
            return jsonify({'error': 'URLs list is required'}), 400
        
        urls = data['urls']
        if not isinstance(urls, list) or len(urls) == 0:
            return jsonify({'error': 'URLs must be a non-empty list'}), 400
        
        if len(urls) > 50:  # Limit batch size
            return jsonify({'error': 'Maximum 50 URLs allowed per batch'}), 400
        
        results = []
        for url in urls:
            if isinstance(url, str) and url.strip():
                url = url.strip()
                if not re.match(r'^https?://', url):
                    url = 'http://' + url
                result = detector.predict_url(url)
                results.append({
                    'url': url,
                    'result': result
                })
            else:
                results.append({
                    'url': url,
                    'result': {'error': 'Invalid URL format'}
                })
        
        return jsonify({
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in batch_analyze: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/retrain', methods=['POST'])
def retrain_model():
    try:
        data = request.get_json()
        training_data = data.get('training_data') if data else None
        
        detector.train_url_model(training_data)
        
        return jsonify({
            'message': 'Model retrained successfully',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in retrain_model: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)