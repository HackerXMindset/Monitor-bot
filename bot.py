import re
import logging
import asyncio
import aiohttp
from datetime import datetime, timedelta
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.sync import TelegramClient as BotClient
from collections import deque, defaultdict
import json

# Load configuration from config.json
with open('config.json', 'r') as f:
    config = json.load(f)

API_ID = config['API_ID']
API_HASH = config['API_HASH']
STRING_SESSIONS = config['STRING_SESSIONS']
ALERT_CHANNEL = config['ALERT_CHANNEL']
ADMIN_USERS = config['ADMIN_USERS']
BOT_TOKEN = config['BOT_TOKEN']

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create clients dictionary
clients = {}
sessions = {}

# Define target users and alert channel
TARGET_USERS = set(['targetUser1', 'targetUser2', 'targetUser3'])
MONITORED_CHATS = defaultdict(list)
NEW_USERS = {}
USER_ACTIVITY = {}
CRYPTO_PATTERNS = {
    "bitcoin": re.compile(r"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}"),
    "ethereum": re.compile(r"0x[a-fA-F0-9]{40}"),
    "litecoin": re.compile(r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}")
}
INITIAL_PRICES = {}
PRICE_ALERTS = defaultdict(list)
MAX_REQUESTS_PER_MINUTE = 60
REQUEST_QUEUE = deque()
LAST_REQUEST_TIME = datetime.now()
REQUEST_INTERVAL = timedelta(seconds=60 / MAX_REQUESTS_PER_MINUTE)

# Hardcoded DEX Screener API URL
DEX_SCREENER_API_URL = "https://api.dexscreener.io/latest/dex/pairs/"

# Initialize the bot client
bot = BotClient('bot', API_ID, API_HASH).start(bot_token=BOT_TOKEN)

# Function to fetch the current price of a cryptocurrency from DEX Screener
async def fetch_crypto_price(symbol):
    url = f"{DEX_SCREENER_API_URL}{symbol}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            data = await response.json()
            return data['pair']['priceUsd']

# Function to check for cryptocurrency addresses
def contains_crypto_address(text):
    for name, pattern in CRYPTO_PATTERNS.items():
        if pattern.search(text):
            return name
    return None

# Function to handle rate limiting
async def rate_limited_request(request_func, *args):
    global LAST_REQUEST_TIME
    now = datetime.now()
    time_since_last_request = now - LAST_REQUEST_TIME
    if time_since_last_request < REQUEST_INTERVAL:
        await asyncio.sleep((REQUEST_INTERVAL - time_since_last_request).total_seconds())
    LAST_REQUEST_TIME = datetime.now()
    await request_func(*args)

# Function to calculate hit rate
def calculate_hit_rate(user):
    hits = USER_ACTIVITY[user]['hits']
    total = USER_ACTIVITY[user]['total']
    hit rate = (hits / total) * 100 if total > 0 else 0
    return hit rate

# Handler function for new messages
async def handle_new_message(event, client_id):
    if event.chat_id in MONITORED_CHATS[client_id]:
        sender = await event.get_sender()
        sender_username = sender.username

        # Track new users' activity
        if sender_username in NEW_USERS:
            coin_type = contains crypto_address(event.message.message)
            if coin_type:
                USER_ACTIVITY[sender_username]['hits'] += 1  # Increment hits
                if coin_type not in INITIAL_PRICES:
                    price = await rate_limited_request(fetch_crypto_price, coin_type)
                    INITIAL_PRICES[coin_type] = {'price': price, 'timestamp': datetime.now()}
            USER_ACTIVITY[sender_username]['total'] += 1  # Increment total messages

            # Calculate hit rate
            hit rate = calculate_hit rate(sender_username)

            # Post the Crypto Alert to the alert channel
            alert_message = (
                f"Call by {sender_username}\n"
                f"Coin - {event.message.message}\n"
                f"Hit rate - {hit rate:.2f}%"
            )
            await event.client.send_message(ALERT_CHANNEL, alert_message)

        if sender_username in TARGET_USERS:
            coin_type = contains crypto_address(event.message.message)
            if coin_type:
                logger.info(f"Detected {coin_type} address in message from {sender_username}: {event.message.message}")
                await event.client.send_message(ALERT_CHANNEL, f"Detected {coin_type} address in message from {sender_username}: {event.message.message}")
                await event.client.send_message(ALERT_CHANNEL, "CA")  # Send CA message

# Command handler to add target user
@bot.on(events.NewMessage(pattern='/adduser'))
async def add_user(event):
    if event.is_private and event.sender.username in ADMIN_USERS:
        new_user = event.message.message.split(' ')[1]
        TARGET_USERS.add(new_user)
        await event.respond(f"User {new_user} added to target list.")
    else:
        await event.respond("Unauthorized request.")

# Command handler to remove target user
@bot.on(events.NewMessage(pattern='/removeuser'))
async def remove_user(event):
    if event.is_private and event.sender.username in ADMIN_USERS:
        user to remove = event.message.message.split(' ')[1]
        TARGET_USERS.discard(user to remove)
        await event.respond(f"User {user to remove} removed from target list.")
    else:
        await event.respond("Unauthorized request.")

# Command handler to list target users
@bot.on(events.NewMessage(pattern='/listusers'))
async def list_users(event):
    if event.is_private:
        users list = '\n'.join(TARGET_USERS)
        await event.respond(f"Current target users:\n{users list}")

# Command handler to add a chat to monitor
@bot.on(events.NewMessage(pattern='/addchat'))
async def add_chat(event):
    if event.is_private and event.sender.username in ADMIN_USERS:
        chat_id = int(event.message.message.split(' ')[1])
        client_id = event.message.message.split(' ')[2]
        if len(MONITORED_CHATS[client_id]) < 10:
            MONITORED_CHATS[client_id].append(chat_id)
            await event.respond(f"Chat {chat_id} added to monitoring list for client {client_id}.")
        else:
            await event.respond(f"Client {client_id} is already monitoring 10 chats.")
    else:
        await event.respond("Unauthorized request.")

# Command handler to list monitored chats
@bot.on(events.NewMessage(pattern='/listchats'))
async def list_chats(event):
    if event is private:
        response = ""
        for client_id, chats in MONITORED_CHATS.items():
            response += f"Client {client_id} is monitoring chats: {', '.join(map(str, chats))}\n"
        await event.respond(response)

# Command handler to add a new account
@bot.on(events.NewMessage(pattern='/addaccount'))
async def add_account(event):
    if event is private and event sender username in ADMIN_USERS:
        args = event.message.message.split(' ')
        if len(args) == 5:
            api_id = int(args[1])
            api_hash = args[2]
            string_session = args[3]
            name = args [4]
            client = TelegramClient(StringSession(string_session), api_id, api_hash)
            try:
                await client.start()
                clients[name] = client
                sessions[name] = string_session
                await event.respond(f"Account {name} added and logged in successfully.")
            except Exception as e:
                await event.respond(f"Failed to add account: {str(e)}")
        else:
            await event.respond("Usage: /addaccount <api_id> <api_hash> <string_session> <name>")
    else:
        await event.respond("Unauthorized request.")

# Command handler to set a price alert
@bot.on(events.NewMessage(pattern='/setalert'))
async def set_alert(event):
    if event is private:
        args = event.message.message.split(' ')
        if len(args) == 3:
            coin_type = args[1]
            price_threshold = float(args[2])
            PRICE_ALERTS[coin_type].append({'threshold': price_threshold, 'user': event.sender.username})
            await event.respond(f"Price alert set for {coin_type} at ${price_threshold}")
        else:
            await event respond("Usage: /setalert <coin_type> <price_threshold>")

# Command handler to list all price alerts
@bot.on(events.NewMessage(pattern='/listalerts'))
async def list_alerts(event):
    if event.is private:
        response = "Current price alerts:\n"
        for coin, alerts in PRICE_ALERTS.items():
            response += f"{coin}:\n"
            for alert in alerts:
                response += f" - ${alert['threshold']} (set by {alert['user']})\n"
        await event.respond(response)

# Function to check user activity and send report
async def check_user_activity():
    while True:
        now = datetime.now()
        for user, start time in list(NEW_USERS.items()):
            if now - start time > timedelta(days=7):
                hits = USER_ACTIVITY[user]['hits']
                total = USER_ACTIVITY[user]['total']
                hit rate = (hits / total) * 100 if total > 0 else 0
                report = f"User {user} activity report:\nHits: {hits}\nTotal messages: {total}\nHit rate: {hit rate:.2f}%"
                await bot.send_message(ALERT_CHANNEL, report)
                if hit rate >= 50:
                    await bot.send_message(ALERT_CHANNEL, f"Add user {user} to target list? /adduser {user}")
                del NEW_USERS[user]
                del USER_ACTIVITY[user]
        await asyncio sleep(3600)  # Check every hour

# Function to check coin prices after a week
async def check_coin_prices():
    while True:
        now = datetime.now()
        for coin, data in list(INITIAL_PRICES.items()):
            if now - data['timestamp'] > timedelta(days=7):
                current price = await rate limited_request(fetch_crypto_price, coin)
                initial price = data['price']
                if current price >= 2 * initial price:
                    await bot.send_message(ALERT_CHANNEL, f"Coin {coin} did 2x in the last week!")
                del INITIAL PRICES[coin]
        await asyncio sleep(3600)  # Check every hour

# Function to check price alerts
async def check_price_alerts():
    while True:
        for coin, alerts in PRICE_ALERTS.items():
            current price = await rate limited_request(fetch_crypto_price, coin)
            for alert in alerts:
                if current price >= alert['threshold']:
                    await bot send_message(ALERT_CHANNEL, f"Price alert: {coin} has reached ${current price} (set by {alert['user']})")
                    alerts remove(alert)
        await asyncio sleep(60)  # Check every minute

# Start monitoring
async def start_monitoring():
    for client_id, client in clients.items():
        @client.on(events.NewMessage(incoming=True))
        async def handler(event, client_id=client_id):
            await handle new_message(event, client_id)

        await client.start()
        logger.info(f"Client {client_id} started")

    # Start the user activity check loop
    asyncio create_task(check_user_activity())
    # Start the coin price check loop
    asyncio create_task(check_coin_prices())
    # Start the price alert check loop
    asyncio create_task(check_price_alerts())

    await asyncio gather(*[client run_until_disconnected() for client in clients.values()])

if __name__ == '__main__':
    loop = asyncio get_event_loop()
    loop run_until_complete(start_monitoring())
