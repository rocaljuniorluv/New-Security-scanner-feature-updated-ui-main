import uvicorn
import logging
import sys
import urllib3

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Start the security scanner server"""
    try:
        logger.info("Starting security scanner server...")
        uvicorn.run(
            "security_scanner:app",
            host="127.0.0.1",
            port=8000,
            reload=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error starting server: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 