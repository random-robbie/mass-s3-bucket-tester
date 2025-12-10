# Mass S3 Bucket Tester

A Python 3 security tool for testing AWS S3 buckets for common misconfigurations including public directory listings, bucket availability, and upload permissions.

**⚠️ For Authorized Security Testing Only** - Use this tool only on systems you own or have explicit permission to test.

## Features

- ✅ **No AWS Credentials Required** - Tests for public misconfigurations without any credentials
- 🚀 **Concurrent Testing** - Fast parallel processing with configurable worker threads
- 🌍 **Comprehensive Region Support** - Supports all major AWS regions
- 📊 **Multiple Test Types**:
  - Public directory listing detection
  - Bucket existence verification (NoSuchBucket detection)
  - Access permission checks (403 responses)
  - Optional upload permission testing (requires credentials)
- 🎯 **Flexible Input** - Test single buckets or batch process from files
- 📝 **Detailed Logging** - Organized output files for different findings
- 🐍 **Modern Python 3** - Clean, maintainable code with boto3

## What It Detects

1. **Publicly Listable Buckets** - Buckets that expose their file listings to anyone
2. **Available Bucket Names** - Non-existent buckets that could be hijacked
3. **Private Buckets** - Buckets that exist but deny public access (403)
4. **Uploadable Buckets** - Buckets with public write permissions (optional test)

## Requirements

- Python 3.7+
- pip

## Installation

```bash
# Clone the repository
git clone https://github.com/random-robbie/mass-s3-bucket-tester.git
cd mass-s3-bucket-tester

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Create a file with bucket URLs (one per line)
echo "test-bucket.s3.amazonaws.com" > list.txt
echo "example-bucket.s3.us-west-2.amazonaws.com" >> list.txt

# Run the tester (no credentials needed!)
python3 s3_poc.py -f list.txt
```

## Usage

### Basic Usage (No Credentials Required)

```bash
# Test buckets from default list.txt file
python3 s3_poc.py

# Test buckets from custom file
python3 s3_poc.py -f buckets.txt

# Test a single bucket
python3 s3_poc.py -u test-bucket.s3.amazonaws.com
```

### Advanced Usage

```bash
# Use 10 concurrent workers for faster testing
python3 s3_poc.py -f buckets.txt -w 10

# Adjust timeout for slow connections
python3 s3_poc.py -f buckets.txt -t 20

# Enable verbose logging
python3 s3_poc.py -f buckets.txt -v
```

### Upload Permission Testing (Optional)

```bash
# Test upload permissions with AWS credentials
python3 s3_poc.py -f buckets.txt --test-upload -k YOUR_ACCESS_KEY -s YOUR_SECRET_KEY

# Or use environment variables
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
python3 s3_poc.py -f buckets.txt --test-upload
```

## Command-Line Options

```
-f, --file FILE          File containing bucket URLs (default: list.txt)
-u, --url URL            Single bucket URL to test
-t, --timeout SECONDS    Request timeout in seconds (default: 10)
-w, --workers NUM        Number of concurrent workers (default: 5)
--test-upload            Test upload permissions (requires AWS credentials)
-k, --access-key KEY     AWS access key ID (only needed with --test-upload)
-s, --secret-key KEY     AWS secret access key (only needed with --test-upload)
-v, --verbose            Enable verbose logging
```

## Input File Format

Create a text file with one S3 bucket URL per line:

```
bucket-name.s3.amazonaws.com
another-bucket.s3.us-west-2.amazonaws.com
test-bucket.s3.eu-west-1.amazonaws.com
example.s3-website-us-east-1.amazonaws.com
```

## Output Files

The tool generates three output files:

- **`buckets-list.txt`** - Buckets with public directory listings enabled
- **`buckets-nosuchbucket.txt`** - Non-existent buckets available for registration
- **`buckets-upload.txt`** - Buckets where POC file upload succeeded (only with --test-upload)

## Supported AWS Regions

- US East (N. Virginia) - us-east-1
- US East (Ohio) - us-east-2
- US West (N. California) - us-west-1
- US West (Oregon) - us-west-2
- Canada (Central) - ca-central-1
- Asia Pacific (Mumbai) - ap-south-1
- Asia Pacific (Singapore) - ap-southeast-1
- Asia Pacific (Sydney) - ap-southeast-2
- Asia Pacific (Tokyo) - ap-northeast-1
- Asia Pacific (Seoul) - ap-northeast-2
- Asia Pacific (Osaka) - ap-northeast-3
- Europe (Frankfurt) - eu-central-1
- Europe (Ireland) - eu-west-1
- Europe (London) - eu-west-2
- Europe (Paris) - eu-west-3
- Europe (Stockholm) - eu-north-1
- South America (São Paulo) - sa-east-1

## How It Works

1. **HTTP Requests** - Makes HTTP requests to S3 bucket URLs to check for public access
2. **Response Analysis** - Analyzes responses for XML bucket listings or error messages
3. **Concurrent Processing** - Tests multiple buckets in parallel for faster results
4. **Optional Upload Test** - If credentials provided and --test-upload enabled, attempts to upload a POC file

## Security & Legal Notice

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only.

- Only test buckets you own or have explicit written permission to test
- Unauthorized testing of third-party S3 buckets may violate laws including:
  - Computer Fraud and Abuse Act (CFAA) in the US
  - Computer Misuse Act in the UK
  - Similar laws in other jurisdictions
- Always follow responsible disclosure practices
- Use this tool ethically and legally

## Bug Bounty & Penetration Testing

This tool is useful for:
- Bug bounty programs with in-scope AWS infrastructure
- Authorized penetration testing engagements
- Security assessments of your own infrastructure
- Educational purposes in controlled environments

## Changelog

### Version 2.0 (Latest)
- Complete rewrite in Python 3
- Replaced deprecated boto with boto3
- Added concurrent processing for faster testing
- Removed credential requirement for basic testing
- Added comprehensive CLI with argparse
- Fixed region mapping bugs
- Eliminated code duplication (200+ lines reduced)
- Added support for additional AWS regions
- Improved error handling and logging
- Made upload testing opt-in with --test-upload flag

### Version 1.0
- Initial Python 2 release
- Basic S3 bucket testing functionality

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This tool is provided as-is for educational and authorized security testing purposes.

## Credits

- Original author: [@random-robbie](https://github.com/random-robbie)
- Modernization improvements: Claude Sonnet 4.5

---

**Disclaimer**: The authors and contributors are not responsible for misuse of this tool. Users are solely responsible for ensuring they have proper authorization before testing any systems.
