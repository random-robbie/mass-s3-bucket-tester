#!/usr/bin/env python3
"""
S3 Bucket Security Testing Tool
Tests S3 buckets for directory listings, upload permissions, and availability for hijacking.
"""

import os
import sys
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple
import re

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import requests
import colorama
from colorama import Fore, Style
colorama.init(autoreset=True)


class S3BucketTester:
    """S3 Bucket security tester for authorized penetration testing."""

    # Comprehensive region mapping for S3 bucket URLs
    REGION_PATTERNS = {
        r's3-website-us-east-1': 'us-east-1',
        r's3\.us-east-2\.amazonaws\.com': 'us-east-2',
        r's3\.amazonaws\.com': 'us-east-1',
        r's3\.us-west-1\.amazonaws\.com': 'us-west-1',
        r's3\.us-west-2\.amazonaws\.com': 'us-west-2',
        r's3-us-west-2': 'us-west-2',
        r's3-website-us-west-2': 'us-west-2',
        r's3\.ca-central-1\.amazonaws\.com': 'ca-central-1',
        r's3\.ap-south-1\.amazonaws\.com': 'ap-south-1',
        r's3\.ap-southeast-1\.amazonaws\.com': 'ap-southeast-1',
        r's3\.ap-southeast-2\.amazonaws\.com': 'ap-southeast-2',
        r's3\.ap-northeast-1\.amazonaws\.com': 'ap-northeast-1',
        r's3-website-ap-northeast': 'ap-northeast-1',
        r's3\.ap-northeast-2\.amazonaws\.com': 'ap-northeast-2',
        r's3\.ap-northeast-3\.amazonaws\.com': 'ap-northeast-3',
        r's3\.eu-central-1\.amazonaws\.com': 'eu-central-1',
        r's3-eu-west-1': 'eu-west-1',
        r's3\.eu-west-1\.amazonaws\.com': 'eu-west-1',
        r's3\.eu-west-2\.amazonaws\.com': 'eu-west-2',
        r's3\.eu-west-3\.amazonaws\.com': 'eu-west-3',
        r's3\.eu-north-1\.amazonaws\.com': 'eu-north-1',
        r's3\.sa-east-1\.amazonaws\.com': 'sa-east-1',
    }

    def __init__(self, aws_access_key: Optional[str] = None,
                 aws_secret_key: Optional[str] = None,
                 timeout: int = 10,
                 max_workers: int = 5,
                 test_upload: bool = False):
        """
        Initialize S3 Bucket Tester.

        Args:
            aws_access_key: AWS access key ID (optional, only needed for upload testing)
            aws_secret_key: AWS secret access key (optional, only needed for upload testing)
            timeout: Request timeout in seconds
            max_workers: Maximum number of concurrent workers
            test_upload: If True, attempt to upload test files (requires credentials)
        """
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.timeout = timeout
        self.max_workers = max_workers
        self.test_upload = test_upload

        # Setup logging
        self.logger = logging.getLogger(__name__)

        # Output files
        self.listable_file = "buckets-list.txt"
        self.uploadable_file = "buckets-upload.txt"
        self.nosuchbucket_file = "buckets-nosuchbucket.txt"

        # Session for HTTP requests
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
            "Connection": "close",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate"
        })

    def parse_bucket_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Parse S3 bucket URL to extract bucket name and region.

        Args:
            url: S3 bucket URL

        Returns:
            Tuple of (bucket_name, region) or (None, None) if parsing fails
        """
        url = url.strip()

        # Try each pattern
        for pattern, region in self.REGION_PATTERNS.items():
            if re.search(pattern, url):
                # Extract bucket name
                parts = re.split(pattern, url)
                if len(parts) >= 1:
                    bucket_name = parts[0].rstrip('.')
                    return bucket_name, region

        # Fallback for standard format
        if '.s3.amazonaws.com' in url or 's3.amazonaws.com' in url:
            bucket_name = url.split('.s3.amazonaws.com')[0]
            if not bucket_name:
                bucket_name = url.split('s3.amazonaws.com/')[1] if '/' in url else None
            return bucket_name, 'us-east-1'

        self.logger.warning(f"Could not parse bucket URL: {url}")
        return None, None

    def check_bucket_listing(self, url: str) -> Tuple[bool, str]:
        """
        Check if S3 bucket has directory listing enabled.

        Args:
            url: S3 bucket URL

        Returns:
            Tuple of (exists, status) where status is 'listable', 'forbidden', or 'nosuchbucket'
        """
        try:
            response = self.session.get(f"http://{url}", timeout=self.timeout)
            content = response.text

            if "<ListBucketResult xmlns" in content:
                self.write_result(self.listable_file, url, "File Listings Enabled")
                print(f"{Fore.GREEN}[+] S3 Bucket Lists Files: {url}")
                return True, 'listable'

            if "Code: NoSuchBucket" in content or "NoSuchBucket" in content:
                self.write_result(self.nosuchbucket_file, url, "Bucket Up for Grabs")
                print(f"{Fore.GREEN}[+] Bucket Available for Hijacking: {url}")
                return False, 'nosuchbucket'

            if response.status_code == 403:
                print(f"{Fore.YELLOW}[*] Bucket Exists (Access Denied): {url}")
                return True, 'forbidden'

            print(f"{Fore.YELLOW}[*] Unknown Status ({response.status_code}): {url}")
            return False, 'unknown'

        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout checking bucket: {url}")
            print(f"{Fore.RED}[-] Timeout: {url}")
            return False, 'timeout'
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error checking bucket {url}: {str(e)}")
            print(f"{Fore.RED}[-] Error: {url}")
            return False, 'error'

    def check_bucket_upload(self, bucket_name: str, url: str, region: str) -> bool:
        """
        Check if bucket allows file uploads.

        Args:
            bucket_name: Name of the S3 bucket
            url: Full bucket URL
            region: AWS region

        Returns:
            True if upload successful, False otherwise
        """
        if not self.aws_access_key or not self.aws_secret_key:
            self.logger.debug("AWS credentials not provided, skipping upload test")
            return False

        try:
            # Create S3 client with boto3
            s3_client = boto3.client(
                's3',
                region_name=region,
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key
            )

            # Create POC file content
            poc_content = "This is a proof of concept file uploaded for security testing purposes."
            key_name = 'poc.txt'

            # Try to upload
            s3_client.put_object(
                Bucket=bucket_name,
                Key=key_name,
                Body=poc_content,
                ACL='public-read'
            )

            self.write_result(self.uploadable_file, url, f"POC uploaded: http://{url}/{key_name}")
            print(f"{Fore.GREEN}[+] POC Uploaded Successfully: http://{url}/{key_name}")
            return True

        except NoCredentialsError:
            self.logger.error("AWS credentials not found")
            print(f"{Fore.RED}[-] AWS credentials not configured")
            return False
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            self.logger.debug(f"Upload failed for {bucket_name}: {error_code}")
            print(f"{Fore.RED}[-] Upload Denied ({error_code}): {bucket_name}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error uploading to {bucket_name}: {str(e)}")
            print(f"{Fore.RED}[-] Upload Error: {bucket_name}")
            return False

    def write_result(self, filename: str, url: str, message: str):
        """Write result to output file."""
        try:
            with open(filename, 'a') as f:
                f.write(f"[*] {message} - http://{url} [*]\n")
        except IOError as e:
            self.logger.error(f"Error writing to {filename}: {str(e)}")

    def test_bucket(self, url: str):
        """
        Test a single S3 bucket for vulnerabilities.

        Args:
            url: S3 bucket URL to test
        """
        url = url.strip()
        if not url:
            return

        bucket_name, region = self.parse_bucket_url(url)

        if not bucket_name or not region:
            print(f"{Fore.RED}[-] Could not parse bucket URL: {url}")
            return

        print(f"\n{Fore.YELLOW}[*] Testing Bucket: {bucket_name} (Region: {region}) [*]")

        # Check listing permissions
        exists, status = self.check_bucket_listing(url)

        # If bucket exists and test_upload is enabled, try upload
        if self.test_upload and exists and status != 'nosuchbucket':
            self.check_bucket_upload(bucket_name, url, region)

    def test_buckets_from_file(self, filename: str):
        """
        Test multiple S3 buckets from a file.

        Args:
            filename: Path to file containing bucket URLs (one per line)
        """
        if not os.path.exists(filename):
            print(f"{Fore.RED}[-] File not found: {filename}")
            return

        with open(filename, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"{Fore.CYAN}[*] Loaded {len(urls)} bucket URLs from {filename}")
        print(f"{Fore.CYAN}[*] Testing with {self.max_workers} concurrent workers...\n")

        if self.max_workers > 1:
            # Concurrent execution
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self.test_bucket, url): url for url in urls}
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        url = futures[future]
                        self.logger.error(f"Error testing {url}: {str(e)}")
        else:
            # Sequential execution
            for url in urls:
                self.test_bucket(url)

        print(f"\n{Fore.CYAN}[*] Testing complete!")
        print(f"{Fore.CYAN}[*] Check output files for results:")
        print(f"    - {self.listable_file}")
        print(f"    - {self.uploadable_file}")
        print(f"    - {self.nosuchbucket_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='S3 Bucket Security Testing Tool - Test S3 buckets for misconfigurations (NO CREDENTIALS REQUIRED)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f buckets.txt
  %(prog)s -u bucket-name.s3.amazonaws.com
  %(prog)s -f buckets.txt -w 10
  %(prog)s -f buckets.txt --test-upload -k YOUR_KEY -s YOUR_SECRET

Note:
  - The tool checks for public bucket listings and availability WITHOUT credentials
  - Use --test-upload only if you want to test upload permissions (requires AWS credentials)

Environment Variables (optional, only for upload testing):
  AWS_ACCESS_KEY_ID     - AWS access key ID
  AWS_SECRET_ACCESS_KEY - AWS secret access key
        """
    )

    parser.add_argument('-f', '--file', default='list.txt',
                        help='File containing bucket URLs (default: list.txt)')
    parser.add_argument('-u', '--url',
                        help='Single bucket URL to test')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('-w', '--workers', type=int, default=5,
                        help='Number of concurrent workers (default: 5)')
    parser.add_argument('--test-upload', action='store_true',
                        help='Test upload permissions (requires AWS credentials via -k/-s or env vars)')
    parser.add_argument('-k', '--access-key',
                        help='AWS access key ID (only needed with --test-upload)')
    parser.add_argument('-s', '--secret-key',
                        help='AWS secret access key (only needed with --test-upload)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Create tester instance
    tester = S3BucketTester(
        aws_access_key=args.access_key,
        aws_secret_key=args.secret_key,
        timeout=args.timeout,
        max_workers=args.workers,
        test_upload=args.test_upload
    )

    # Print banner
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}S3 Bucket Security Testing Tool")
    print(f"{Fore.CYAN}For Authorized Penetration Testing Only")
    print(f"{Fore.CYAN}{'='*60}\n")

    if args.test_upload:
        if not args.access_key and not args.secret_key:
            print(f"{Fore.YELLOW}[*] UPLOAD TEST MODE: No credentials provided, will skip upload tests\n")
        else:
            print(f"{Fore.YELLOW}[*] UPLOAD TEST MODE: Will attempt to upload test files\n")
    else:
        print(f"{Fore.CYAN}[*] Checking for public bucket misconfigurations (no credentials required)\n")

    # Test bucket(s)
    if args.url:
        tester.test_bucket(args.url)
    else:
        tester.test_buckets_from_file(args.file)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {str(e)}")
        logging.exception("Fatal error")
        sys.exit(1)
