import re
import logging
import asyncio
import aiohttp
from datetime import datetime, timedelta
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from collections import deque, defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Telegram API credentials
STRING_SESSIONS = [
    'your_string_session_1',
    'your_string_session_2',
    # Add more string sessions for additional userbots
]

# Create clients
clients = []

for session in STRING_SESSIONS:
    client = TelegramClient(StringSession(session), 'your_api_id', 'your_api_hash')
    clients.append(client)

# Define target users and alert channel
TARGET_USERS = set(['targetUser1', 'targetUser2', 'targetUser3'])
ALERT_CHANNEL = 'your_alert_channel'
MONITORED_CHATS = {}
NEW_USERS = {}
USER_ACTIVITY = {}
ADMIN_USERS = ['adminUser1', 'adminUser2']  # List of admin usernames

# Define regex patterns for cryptocurrency addresses
CRYPTO_PATTERNS = {
    "bitcoin": re.compile(r"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}"),
    "ethereum": re.compile(r"0x[a-fA-F0-9]{40}"),
    "litecoin": re.compile(r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}"),
    # Add more patterns as needed
}

# Dictionary to store initial prices
INITIAL_PRICES = {}
# Dictionary to store price alerts
PRICE_ALERTS = defaultdict(list)

# Rate limiting parameters
MAX_REQUESTS_PER_MINUTE = 60
REQUEST_QUEUE = deque()
LAST_REQUEST_TIME = datetime.now()
REQUEST_INTERVAL = timedelta(seconds=60 / MAX_REQUESTS_PER_MINUTE)

# Function to fetch the current price of a cryptocurrency from DEX Screener
async def fetch_crypto_price(symbol):
    url = f"https://api.dexscreener.io/latest/dex/pairs/{symbol}"
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

# Handler function for new messages
async def handle_new_message(event, client_id):
    if client_id in MONITORED_CHATS and event.chat_id in MONITORED_CHATS[client_id]:
        sender = await event.get_sender()
        sender_username = sender.username

        # Track new users' activity
        if sender_username in NEW_USERS:
            coin_type = contains_crypto_address(event.message.message)
            if coin_type:
                USER_ACTIVITY[sender_username]['hits'] += 2  # Consider each hit as 2 points
                if coin_type not in INITIAL_PRICES:
                    price = await rate_limited_request(fetch_crypto_price, coin_type)
                    INITIAL_PRICES[coin_type] = {'price': price, 'timestamp': datetime.now()}
            USER_ACTIVITY[sender_username]['total'] += 1

        if sender_username in TARGET_USERS:
            coin_type = contains_crypto_address(event.message.message)
            if coin_type:
                logger.info(f"Detected {coin_type} address in message from {sender_username}: {event.message.message}")
                await event.client.send_message(ALERT_CHANNEL, f"Detected {coin_type} address in message from {sender_username}: {event.message.message}")
                await event.client.send_message(ALERT_CHANNEL, "CA")  # Send CA message

# Command handler to add target user
@events.register(events.NewMessage(pattern='/adduser'))
async def add_user(event):
    if event.is_private and event.sender.username in ADMIN_USERS:
        new_user = event.message.message.split(' ')[1]
        TARGET_USERS.add(new_user)
        await event.respond(f"User {new_user} added to target list.")
    else:
        await event.respond("Unauthorized request.")

# Command handler to remove target user
@events.register(events.NewMessage(pattern='/removeuser'))
async def remove_user(event):
    if event.is_private and event.sender.username in ADMIN_USERS:
        user_to_remove = event.message.message.split(' ')[1]
        TARGET_USERS.discard(user_to_remove)
        await event.respond(f"User {user_to_remove} removed from target list.")
    else:
        await event.respond("Unauthorized request.")

# Command handler to list target users
@events.register(events.NewMessage(pattern='/listusers'))
async def list_users(event):
    if event.is_private:
        users_list = '\n'.join(TARGET_USERS)
        await event.respond(f"Current target users:\n{users_list}")

# Command handler to add a chat to monitor
@events.register(events.NewMessage(pattern='/addchat'))
async def add_chat(event):
    if event.is_private and event.sender.username in ADMIN_USERS:
        chat_id = int(event.message.message.split(' ')[1])
        client_id = int(event.message.message.split(' ')[2])
        if client_id not in MONITORED_CHATS:
            MONITORED_CHATS[client_id] = []
        MONITORED_CHATS[client_id].append(chat_id)
        await event.respond(f"Chat {chat_id} added to monitoring list for client {client_id}.")
    else:
        await event.respond("Unauthorized request.")

# Command handler to list monitored chats
@events.register(events.NewMessage(pattern='/listchats'))
async def list_chats(event):
    if event.is_private:
        response = ""
        for client_id, chats in MONITORED_CHATS.items():
            response += f"Client {client_id} is monitoring chats: {', '.join(map(str, chats))}\n"
        await event.respond(response)

# Command handler to add a new account
@events.register(events.NewMessage(pattern='/addaccount'))
async def add_account(event):
    if event.is_private and event.sender.username in ADMIN_USERS:
        string_session = event.message.message.split(' ')[1]
        client = TelegramClient(StringSession(string_session), 'your_api_id', 'your_api_hash')
        clients.append(client)
        await client.start()
        await event.respond(f"Account added and started.")
    else:
        await event.respond("Unauthorized request.")

# Command handler to start tracking a new user
@events.register(events.NewMessage(pattern='/trackuser'))
async def track_user(event):
    if event.is_private and event.sender.username in ADMIN_USERS:
        new_user = event.message.message.split(' ')[1]
        NEW_USERS[new_user] = datetime.now()
        USER_ACTIVITY[new_user] = {'hits': 0, 'total': 0}
        await event.respond(f"User {new_user} is now being tracked.")
    else:
        await event.respond("Unauthorized request.")

# Command handler to set a price alert
@events.register(events.NewMessage(pattern='/setalert'))
async def set_alert(event):
    if event.is_private:
        args = event.message.message.split(' ')
        if len(args) == 3:
            coin_type = args[1]
            price_threshold = float(args[2])
            PRICE_ALERTS[coin_type].append({'threshold': price_threshold, 'user': event.sender.username})
            await event.respond(f"Price alert set for {coin_type} at ${price_threshold}")
        else:
            await event.respond("Usage: /setalert <coin_type> <price_threshold>")

# Command handler to list all price alerts
@events.register(events.NewMessage(pattern='/listalerts'))
async def list_alerts(event):
    if event.is_private:
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
        for user, start_time in list(NEW_USERS.items()):
            if now - start_time > timedelta(days=7):
                hits = USER_ACTIVITY[user]['hits']
                total = USER_ACTIVITY[user]['total']
                hit_rate = (hits / total) * 100 if total > 0 else 0
                report = f"User {user} activity report:\nHits: {hits}\nTotal messages: {total}\nHit rate: {hit_rate:.2f}%"
                await clients[0].send_message(ALERT_CHANNEL, report)
                if hit_rate >= 50:
                    await clients[0].send_message(ALERT_CHANNEL, f"Add user {user} to target list? /adduser {user}")
                del NEW_USERS[user]
                del USER_ACTIVITY[user]
        await asyncio.sleep(3600)  # Check every hour

# Function to check coin prices after a week
async def check_coin_prices():
    while True:
        now = datetime.now()
        for coin, data in list(INITIAL_PRICES.items()):
            if now - data['timestamp'] > timedelta(days=7):
                current_price = await rate_limited_request(fetch_crypto_price, coin)
                initial_price = data['price']
                if current_price >= 2 * initial_price:
                    await clients[0].send_message(ALERT_CHANNEL, f"Coin {coin} did 2x in the last week!")
                del INITIAL_PRICES[coin]
        await asyncio.sleep(3600)  # Check every hour

# Function to check price alerts
async def check_price_alerts():
    while True:
        for coin, alerts in PRICE_ALERTS.items():
            current_price = await rate_limited_request(fetch_crypto_price, coin)
            for alert in alerts:
                if current_price >= alert['threshold']:
                    await clients[0].send_message(ALERT_CHANNEL, f"Price alert: {coin} has reached ${current_price} (set by {alert['user']})")
                    alerts.remove(alert)
        await asyncio.sleep(60)  # Check every minute

# Start monitoring
async def start_monitoring():
    for i, client in enumerate(clients):
        @client.on(events.NewMessage(incoming=True))
        async def handler(event, client_id=i):
            await handle_new_message(event, client_id)

        await client.start()
        logger.info(f"Client {client.session.filename} started")

    # Start the user activity check loop
    asyncio.create_task(check_user_activity())
    # Start the coin price check loop
    asyncio.create_task(check_coin_prices())
    # Start the price alert check loop
    asyncio.create_task(check_price_alerts())

    await asyncio.gather(*[client.run_until_disconnected() for client in clients])

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(start_monitoring())
