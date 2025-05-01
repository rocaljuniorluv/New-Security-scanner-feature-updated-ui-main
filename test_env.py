from dotenv import load_dotenv
import os

load_dotenv()
 
print("SHODAN_API_KEY:", os.getenv('SHODAN_API_KEY'))
print("ABUSEIPDB_API_KEY:", os.getenv('ABUSEIPDB_API_KEY')) 