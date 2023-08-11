import asyncio
import discord
from dotenv import load_dotenv
import os

load_dotenv()
DISCORD_TOKEN = os.environ.get("TOKEN_")
DISCORD_CHANNEL_ID = int(os.environ.get("CHANNEL_ID"))


async def send_discord_message(message):
    try:
        # Replace 'YOUR_DISCORD_BOT_TOKEN' with your actual Discord bot token
        bot_token = DISCORD_TOKEN
        intents = discord.Intents.default()
        client = discord.Client(intents=intents)

        @client.event
        async def on_ready():
            channel = client.get_channel(DISCORD_CHANNEL_ID)
            await channel.send(message)
            await client.close()

        async with client:
            await client.start(bot_token)
    except Exception as e:
        print("Error sending message to Discord:", e)
