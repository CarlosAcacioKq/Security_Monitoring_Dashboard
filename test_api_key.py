#!/usr/bin/env python3
"""
Quick test of AbuseIPDB API key
"""

import os
import requests

def test_abuseipdb_api():
    """Test if the API key works"""
    
    # Set the API key directly for testing
    api_key = "7b530d5b96dbeb865c301954ea2f3c078e6aa83e878211e4e71b78ec4a20acb349d8c31ca6531215"
    
    print("Testing AbuseIPDB API key...")
    print(f"API Key: {api_key[:10]}...{api_key[-10:]}")
    print()
    
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    
    params = {
        'confidenceMinimum': 75,
        'limit': 10,
        'plaintext': True
    }
    
    try:
        print("Making API request...")
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("SUCCESS! API key is working")
            print(f"Response length: {len(response.text)} characters")
            
            try:
                data = response.json()
                print(f"Retrieved {len(data.get('data', []))} threat IPs")
            except Exception as json_error:
                print(f"JSON parsing issue: {json_error}")
                print("Raw response preview:", response.text[:200])
            
            # Show first 3 IPs
            for i, ip_data in enumerate(data.get('data', [])[:3]):
                ip = ip_data.get('ipAddress')
                confidence = ip_data.get('abuseConfidencePercentage', 0)
                country = ip_data.get('countryCode', 'Unknown')
                print(f"  {i+1}. {ip} (Confidence: {confidence}%, Country: {country})")
                
            return True
            
        elif response.status_code == 401:
            print("ERROR: Invalid API key")
            return False
        elif response.status_code == 429:
            print("ERROR: Rate limit exceeded")
            return False
        else:
            print(f"ERROR: HTTP {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"ERROR: {e}")
        return False

if __name__ == "__main__":
    print("ABUSEIPDB API KEY TEST")
    print("=" * 25)
    
    success = test_abuseipdb_api()
    
    print()
    if success:
        print("API key is VALID! Ready to integrate real threat data.")
    else:
        print("API key test FAILED. Please check your key.")