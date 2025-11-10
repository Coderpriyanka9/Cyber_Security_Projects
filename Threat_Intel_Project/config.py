import os
from dotenv import load_dotenv

load_dotenv()

# API and DB configuration
THREAT_FEED_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
API_KEY = os.getenv("OTX_API_KEY")
DB_PATH = "threat_intel.db"
REPORT_FILE = "threat_report.csv"
