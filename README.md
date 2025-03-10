# Telegram Userbot Monitor

This project is a Telegram userbot monitor that tracks messages for cryptocurrency addresses and provides various alerts and reports. It uses the Telethon library to interact with the Telegram API.

## Features

- Monitor multiple chats for cryptocurrency addresses
- Detect and alert on cryptocurrency addresses
- Track user activity and calculate hit rates
- Set and manage price alerts for cryptocurrencies
- Admin commands to manage target users, monitored chats, and userbot accounts

## Setup

1. Clone the repository:
   ```sh
   git clone https://github.com/HackerXMindset/telegram-userbot-monitor.git
   cd telegram-userbot-monitor
   ```

2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

3. Configure the bot:
   - Edit the `config.json` file with your API ID, API Hash, String Sessions, Alert Channel, Bot Token, and Admin Users.

## Running the Bot

Run the bot using Python:
```sh
python telegram_userbot.py
```

## Admin Commands

- `/addaccount <api_id> <api_hash> <string_session> <name>`: Add a new userbot account.
- `/adduser <username>`: Add a target user.
- `/removeuser <username>`: Remove a target user.
- `/listusers`: List all target users.
- `/addchat <chat_id> <client_id>`: Add a chat to monitor.
- `/listchats`: List all monitored chats.
- `/setalert <coin_type> <price_threshold>`: Set a price alert.
- `/listalerts`: List all price alerts.

## License

This project is licensed under the MIT License.
