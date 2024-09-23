from discord_webhook import DiscordWebhook, DiscordEmbed
import locale
locale.setlocale(locale.LC_TIME, 'fr_FR')
from datetime import datetime

webhook_url = "https://discord.com/api/webhooks/1286376044122603590/pFPOJid1FtgqbV7OtKhgivL-eiSc393d3idklHLWEGKGyJimmMylS_v13bdm3mWBWSrf"
def send_message():
    webhook = DiscordWebhook(url=webhook_url, content="⚠️Alerte : Une activité suspects a été détectée.")
    embed = DiscordEmbed(title="Alerte Sécurité", description="Une tentative d'intrusion a été détectée.",
                         color='03b2f8')
    # Ajouter des champs au message enrichi
    embed.add_embed_field(name="Type d'attaque", value="Scanne de port")
    embed.add_embed_field(name="Adresse IP", value="192.168.53.103")
    embed.add_embed_field(name="Horodatage", value=datetime.now().strftime("%d %B %Y %Hh:%Mm:%Ss"))
    # Ajouter l'embed au webhook
    webhook.add_embed(embed)

    # Envoyer le message
    response = webhook.execute()

send_message()