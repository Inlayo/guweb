import smtplib
import imaplib
from objects import glob
from objects import logUtils as log
from discord_webhook import DiscordWebhook, DiscordEmbed

sender_email = glob.config.SenderEmail
sender_password = glob.config.SenderEmailPassword

def mailSend(to_email, msg, type=""):
    sc = 200
    # SMTP 서버에 연결 및 이메일 전송
    try:
        smtp = smtplib.SMTP_SSL("smtp.daum.net", 465)
        smtp.login(sender_email, sender_password)
        smtp.sendmail(sender_email, to_email, msg.as_string())
        smtp.quit()
        log.info(f"{type} 이메일 전송 성공")
    except Exception as e:
        #SMTPDataError(code, resp), smtplib.SMTPDataError
        log.error(f"{type} 이메일 전송 실패 : {e}")
        sc = e

    # 보낸메일함에 복사
    try:
        if sc == 200:
            imap = imaplib.IMAP4_SSL("imap.daum.net", 993)
            imap.login(sender_email, sender_password)
            imap.append("Sent", None, None, msg.as_bytes())
            log.info("보낸메일함 복사 성공!")
        else:
            log.warning("메일 전송 실패함에 따라 보낸메일함 복사는 하지 않음")
    except Exception as e:
        log.error(f"보낸메일함 복사 실패 : {e}")
        sc = e

    # 디코 웹훅 전송
    try:
        if sc != 200: raise sc
        msg = msg.as_string()
        if len(msg) > 4096: msg = msg[:4096] #description 길이제한
        webhook = DiscordWebhook(url=glob.config.DISCORD_EMAIL_LOG_WEBHOOK)
        embed = DiscordEmbed(description=msg, color=242424)
        embed.set_author(name=f"BanchoBot Sent {type} email", url=f"https://osu.{glob.config.domain}/u/1", icon_url=f"https://a.{glob.config.domain}/1")
        embed.set_footer(text="via guweb!")
        webhook.add_embed(embed)
        webhook.execute()
    except Exception as e: log.error(f"디코 웹훅 전송 실패! | {e}")
    return sc