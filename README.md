# Network Diagnostic Tool

A comprehensive web application for network analysis, SSL certificate testing, mobile balance checking, and secure IP storage. Created by King85 for advanced network diagnostics and security assessment.

## 🚀 Deployed on Vercel

This application is deployed and accessible at: **[Live Demo](https://your-app-name.vercel.app)**

## Features

### 🔍 Network Diagnostics
- **Ping Testing**: Advanced ping with statistics and packet loss analysis
- **DNS Lookup**: Comprehensive DNS resolution with all record types
- **Traceroute**: Network path mapping and hop analysis
- **WHOIS Lookup**: Domain ownership and registration information
- **SSL Certificate Check**: Professional SSL validation and security details
- **Advanced Analysis**: Complete network and security assessment

### 📱 Mobile Balance Checking
- **Econet Support**: Airtime and bundle balance checking via USSD
- **NetOne Support**: Airtime and OneFusion balance checking
- **USSD Integration**: Simulated USSD gateway functionality
- **Balance History**: Complete audit trail of all balance checks

### 🔒 Secure IP Storage
- **Password Protection**: Authentication required for IP data access
- **Secure Database**: Encrypted storage of all test results
- **Access Logging**: Complete audit trail of user activities
- **Export Functionality**: Download IP data securely

### 🛡️ Security Features
- **User Authentication**: Secure login system with bcrypt password hashing
- **Session Management**: Flask-Login for secure user sessions
- **Access Control**: Role-based permissions and admin controls
- **Audit Trail**: Complete logging of all system access

## 🌐 Live Deployment

This application is deployed on Vercel and accessible at:
- **URL**: `https://your-app-name.vercel.app`
- **Login**: Username: `admin`, Password: `admin123`
- **Features**: All network diagnostic tools available

## 📋 Quick Start

### Using the Live App
1. Visit the deployed URL
2. Login with admin credentials
3. Use any diagnostic tool:
   - Domain analysis
   - Network testing
   - Balance checking
   - Secure IP access

### Local Development
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the app: `python app.py`
4. Access at `http://localhost:5000`

## 🛠️ Technical Stack

- **Backend**: Flask (Python)
- **Database**: SQLite with secure storage
- **Authentication**: Flask-Login with bcrypt
- **Frontend**: Bootstrap 5 with responsive design
- **Deployment**: Vercel serverless functions
- **Security**: Cryptographic encryption and secure sessions

## 📱 API Endpoints

### Network Diagnostics
- `POST /api/ping-test` - Ping testing with statistics
- `POST /api/dns-lookup` - DNS resolution
- `POST /api/traceroute` - Network path analysis
- `POST /api/whois` - Domain information
- `POST /api/ssl-checker` - SSL certificate validation
- `POST /api/comprehensive-test` - Complete network analysis

### Balance Checking
- `POST /api/balance-check` - Mobile balance checking
- `GET /api/balance-history` - Balance check history
- `GET /api/ussd-codes` - Available USSD codes

### Secure Storage
- `GET /api/secure-ips` - Access stored IP data (authenticated)
- `POST /api/store-ip` - Store IP test data (authenticated)
- `GET /api/access-logs` - Access logs (admin only)

## 🔧 Deployment Instructions

### Vercel Deployment
1. Push code to GitHub repository
2. Connect repository to Vercel
3. Configure environment variables
4. Deploy automatically

### Environment Variables
- `FLASK_SECRET_KEY`: Application secret key
- Database is automatically created on first run

## 🎯 Creator Information

**Created by**: King85  
**Alias**: SNI-BUG@King85  
**Expertise**: Network Security, System Administration, Web Development  
**Focus**: Building tools for network analysis and security assessment in emerging markets

## 📄 License

This application is provided for educational and authorized network testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## Features

### 🔍 Network Scanning
- **IP Range Scanning**: Scan any IP range using CIDR notation (e.g., 104.21.0.0/17)
- **ISP-Specific Scanning**: Pre-configured IP ranges for Econet and NetOne networks
- **Reverse DNS Lookup**: Discover domain names associated with IP addresses
- **Multi-threaded Processing**: Fast scanning with configurable thread pool

### 🔒 SSL/TLS Analysis
- **Certificate Validation**: Check SSL certificate validity and expiration
- **Certificate Details**: View subject, issuer, version, and serial number
- **Protocol Information**: TLS protocol version and cipher suite details
- **Subject Alternative Names**: Check for additional domain names

### 🌐 SNI Testing
- **SNI Support Detection**: Test if servers support Server Name Indication
- **Certificate Matching**: Verify correct certificates are served with SNI
- **Comparison Analysis**: Compare certificates with and without SNI

### 📊 Results & Export
- **Real-time Results**: Live display of scanning progress and findings
- **Detailed Reports**: Comprehensive information for each discovered domain
- **Export Options**: Download results as CSV or JSON files
- **Statistics Dashboard**: View scan statistics and success rates

### 🎨 User Interface
- **Responsive Design**: Works on desktop and mobile devices
- **Modern UI**: Bootstrap 5 with custom styling and animations
- **Interactive Elements**: Click-to-scan ISP badges and export buttons
- **Progress Indicators**: Visual feedback during scanning operations

## Installation

1. **Clone or download the application files**
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the web interface**:
   Open your browser and navigate to `http://localhost:5000`

## Usage

### Manual IP Range Scanning
1. Enter an IP range in CIDR format (e.g., `104.21.0.0/17`)
2. Click "Start Scan"
3. Wait for the scan to complete
4. Review results and export if needed

### ISP Network Scanning
1. Click on an ISP badge (Econet or NetOne)
2. The application will automatically scan all configured IP ranges
3. Results will display domains, SSL status, and SNI support
4. Export results for further analysis

### Understanding Results
- **IP Address**: The scanned IP address
- **Domains**: Discovered domain names via reverse DNS
- **SSL Status**: Valid/Invalid with expiration dates
- **SNI Status**: Supported/Not supported with certificate details
- **Certificate Info**: Subject, issuer, protocol version, and cipher suite

## Technical Details

### Supported Zimbabwean ISPs

#### Econet Wireless
- Multiple IP ranges including 41.78.112.0/20, 41.85.0.0/16, 196.4.78.0/24, 197.221.128.0/17
- Covers main network infrastructure and customer ranges

#### NetOne
- Extensive IP ranges including 41.72.0.0/16 through 41.127.0.0/16
- Includes 196.43.192.0/19 and related subnets
- Comprehensive coverage of NetOne network infrastructure

### Network Analysis Capabilities
- **Reverse DNS**: PTR record lookups for domain discovery
- **SSL Handshake**: Full TLS handshake simulation
- **Certificate Parsing**: X.509 certificate analysis
- **SNI Testing**: Hostname-based certificate serving verification
- **Multi-threaded Scanning**: Parallel processing for faster results

### Export Formats

#### CSV Export
Columns: IP Address, Domain, SSL Valid, SSL Subject, SSL Expires, SNI Supported

#### JSON Export
Complete scan results with all SSL and SNI details in structured JSON format

## Dependencies

- **Flask**: Web framework
- **dnspython**: DNS resolution and reverse lookups
- **cryptography**: SSL/TLS certificate handling
- **requests**: HTTP client for additional testing
- **python-whois**: WHOIS information lookup
- **netaddr**: Network address manipulation
- **ipaddress**: IP address and network utilities

## Security Considerations

- All SSL connections use proper certificate validation
- Timeout limits prevent hanging connections
- Thread pool limits prevent resource exhaustion
- Input validation prevents malformed IP ranges
- Error handling ensures graceful failure modes

## Performance Notes

- Scanning large IP ranges may take several minutes
- Thread pool size is configurable (default: 50 threads)
- SSL testing is limited to first 3 domains per IP for performance
- Memory usage scales with number of discovered domains

## Troubleshooting

### Common Issues
1. **DNS Resolution Failures**: Check internet connectivity and DNS settings
2. **SSL Timeouts**: Increase timeout values in the code if needed
3. **Memory Issues**: Reduce thread pool size for large scans
4. **Permission Errors**: Ensure the application can bind to port 5000

### Debug Mode
Run with debug mode enabled for detailed error messages:
```bash
python app.py --debug
```

## License

This application is provided for educational and network analysis purposes. Use responsibly and in accordance with applicable laws and network policies.

## Support

For issues, feature requests, or questions, please refer to the application logs and error messages for troubleshooting information.
