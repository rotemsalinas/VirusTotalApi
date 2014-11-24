#!/usr/bin/python

import os
import sys
import json
import requests
from BeautifulSoup import BeautifulSoup

vtApiKey = ''
vtUsername = ''
vtPassword = ''
vtRefererURL = 'https://www.virustotal.com/?signin=true&next=/intelligence/'
vtSigninURL = 'https://www.virustotal.com/en/account/signin/'
vtSubmissionHashURL = 'https://www.virustotal.com/intelligence/sample/submissions/?hash=%s' 
vtApiUrl = 'https://www.virustotal.com/%s'
vtApiActions = [{'url': 'vtapi/v2/file/scan', 'method': 'POST'}, 
				{'url': 'vtapi/v2/file/scan/upload_url', 'method': 'GET'}, 
				{'url': 'vtapi/v2/file/rescan', 'method': 'POST'}, 
				{'url': 'vtapi/v2/file/rescan/delete', 'method': 'POST'}, 
				{'url': 'vtapi/v2/file/report', 'method': 'GET'}, 
				{'url': 'vtapi/v2/file/behaviour', 'method': 'GET'}, 
				{'url': 'vtapi/v2/file/network-traffic', 'method': 'GET'}, 
				{'url': 'vtapi/v2/file/search', 'method': 'GET'}, 
				{'url': 'vtapi/v2/file/clusters', 'method': 'GET'}, 
				{'url': 'vtapi/v2/file/distribution', 'method': 'GET'}, 
				{'url': 'vtapi/v2/file/download', 'method': 'GET'}, 
				{'url': 'vtapi/v2/url/scan', 'method': 'POST'}, 
				{'url': 'vtapi/v2/url/report', 'method': 'GET'}, 
				{'url': 'vtapi/v2/url/distribution', 'method': 'GET'}, 
				{'url': 'vtapi/v2/ip-address/report', 'method': 'GET'}, 
				{'url': 'vtapi/v2/domain/report', 'method': 'GET'}, 
				{'url': 'vtapi/v2/comments/put', 'method': 'POST'}, 
				{'url': 'vtapi/v2/comments/get', 'method': 'GET'}] 


def CallVirusTotalAPI(apiAction, params, files=None):
	response = None
	url = (vtApiUrl % (apiAction['url']))

	if(apiAction['method'] == 'GET'):		
		response = requests.get(url, params=params)

	if(apiAction['method'] == 'POST'):
		if files:
			response = requests.post(url, files=files, params=params)
		else:
			response = requests.post(url, params=params)

	try:
		return response.json()
	except:
		return response

def GetSubmissionHashes(hash):
	from requests import Request, Session

	params = {'username' : vtUsername, 'password' : vtPassword, 'response_format': 'json'}
	headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "application/json, text/javascript, */*; q=0.01", "Referer": vtRefererURL}

	s = requests.Session()

	resp1 = s.post(vtSigninURL, data=params, headers=headers)
	resp2 = s.get(vtSubmissionHashURL % (hash))

	return htmlTableToList(resp2.text)

def htmlTableToList(html):	
	soup = BeautifulSoup(html)
	table = soup.find("table")

	data = []

	for row in table.findAll('tr')[1:]:
	    col = row.findAll('td')
	    date = col[0].string.strip(' \n')
	    fileName = col[1].find('span').string.strip(' \n')
	    sourceHash = col[2].string.strip(' \n')
	    country = col[3].string.strip(' \n')
	    data.append({'date': date, 'fileName': fileName, 'sourceHash': country, 'sourceHash': country})

	return data

def FileScan(filePath):
	params = {'apikey': vtApiKey}
	files = {'file': (filePath, open(filePath, 'rb'))}
	return CallVirusTotalAPI(vtApiActions[0], params, files)

def FileScanUploadURL():
	params = {'apikey': vtApiKey}
	return CallVirusTotalAPI(vtApiActions[1], params)

def FileRescan(sampleHash):
	params = {'apikey': vtApiKey, 'resource': sampleHash}
	return CallVirusTotalAPI(vtApiActions[2], params)

def FileDeleteRescan(sampleHash):
	params = {'apikey': vtApiKey, 'resource': sampleHash}
	return CallVirusTotalAPI(vtApiActions[3], params)

def FileReport(sampleHash):
	params = {'apikey': vtApiKey, 'resource': sampleHash}
	return CallVirusTotalAPI(vtApiActions[4], params)

def FileBehaviour(sampleHash):
	params = {'apikey': vtApiKey, 'hash': sampleHash}
	return CallVirusTotalAPI(vtApiActions[5], params)	

def FileNetworkTraffic(sampleHash):
	params = {'apikey': vtApiKey, 'hash': sampleHash}
	return CallVirusTotalAPI(vtApiActions[6], params)

def FileSearch(query):
	params = {'apikey': vtApiKey, 'query': query}
	return CallVirusTotalAPI(vtApiActions[7], params)

def FileClusters(date):
	params = {'apikey': vtApiKey, 'date': date}
	return CallVirusTotalAPI(vtApiActions[8], params)

def FileDistribution(boolReports=True):
	params = {'apikey': vtApiKey, 'reports': boolReports.__str__.lower()}
	return CallVirusTotalAPI(vtApiActions[9], params)

def FileDownload(hash):
	params = {'apikey': vtApiKey, 'hash': hash}
	return CallVirusTotalAPI(vtApiActions[10], params)

def UrlScan(url):
	params = {'apikey': vtApiKey, 'resource': url}
	return CallVirusTotalAPI(vtApiActions[11], params)

def UrlReport(url):
	params = {'apikey': vtApiKey, 'url': url}
	return CallVirusTotalAPI(vtApiActions[12], params)

def UrlDistribution(boolReports=True):
	params = {'apikey': vtApiKey, 'reports': boolReports.__str__().lower()}
	return CallVirusTotalAPI(vtApiActions[13], params)

def IpAddressReport(ipAddress):
	params = {'apikey': vtApiKey, 'ip': ipAddress}
	return CallVirusTotalAPI(vtApiActions[14], params)

def DomainReport(domain):
	params = {'apikey': vtApiKey, 'domain': domain}
	return CallVirusTotalAPI(vtApiActions[15], params)

def CommentsPut(sampleHash, comment):
	params = {'apikey': vtApiKey, 'resource': sampleHash, 'comment': comment}
	return CallVirusTotalAPI(vtApiActions[16], params)

def CommentsGet(sampleHash):
	params = {'apikey': vtApiKey, 'resource': sampleHash}
	return CallVirusTotalAPI(vtApiActions[17], params)




