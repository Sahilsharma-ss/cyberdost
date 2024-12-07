import requests
import base64
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Replace with your Bot's token
TELEGRAM_API_TOKEN = '6998747436:AAEbpRpbx8p4E3uzJ1ulAWKnSAeIpQNqDlY'

# VirusTotal API endpoint and key
VIRUSTOTAL_API_KEY = '7b6c047f87ba687a0f9e0bcc705456a410ee74ed5df66809fda64fc3ff4bda93'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls/'

# Function to check phishing URLs using VirusTotal API
def check_url(url):
    # Encode the URL to Base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    
    # Send a request to VirusTotal API
    response = requests.get(VIRUSTOTAL_URL + url_id, headers=headers)
    return response.json()

# Define function for /start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome to CyberDost! Send me a URL, and I will check if it's phishing.")

# Define function for checking URLs
async def check_url_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text
    result = check_url(url)
    
    if 'data' in result and result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
        await update.message.reply_text(f"Warning: {url} is potentially a phishing site!")
    else:
        await update.message.reply_text(f"{url} seems safe, no threats detected.")

# Define the main function to handle commands and messages
def main():
    # Create the Application instance using the bot token
    application = Application.builder().token(TELEGRAM_API_TOKEN).build()
    
    # Add handlers for commands and messages
    application.add_handler(CommandHandler('start', start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_url_command))
    
    # Start the bot's polling loop
    application.run_polling()

if __name__ == '__main__':
    main()
