from discord_webhook import DiscordWebhook, DiscordEmbed
import locale
from datetime import datetime
import platform

if platform.system() == "Windows":
    locale.setlocale(locale.LC_TIME, 'fr_FR')
elif platform.system() == "Linux":
    locale.setlocale(locale.LC_TIME, 'fr_FR.utf8')

webhook_url = "https://discord.com/api/webhooks/1304604530264244234/WuZ5WCchXcklJ7yBmKShZGr_C7IrVyfnoIotu76Jdz_iueiAhWmjU-sYFM3b21Iif6ya"
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
