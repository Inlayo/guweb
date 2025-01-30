import smtplib
import imaplib
from objects import glob
import logUtils as log
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

        if type == "AutoBan" or type == "Ban":
            origin = msg.as_string()
            msg = origin[:origin.find("Content-Type: text/html;")]
            msg += origin[origin.find('<a id="Reason for sending mail"'):origin.find('</a>', origin.find('<a id="Reason for sending mail"')) + 4]
        else: msg = msg.as_string()

        webhook = DiscordWebhook(url=UserConfig["AdminLogWebhook"])
        embed = DiscordEmbed(description=msg, color=242424)
        embed.set_author(name=f"{sess['AccountName']} Sent {type} email", url=f"{UserConfig['ServerURL']}u/{sess['AccountId']}", icon_url=f"{UserConfig['AvatarServer']}999")
        embed.set_footer(text="via RealistikPanel!")
        webhook.add_embed(embed)
        webhook.execute()
        print(" * Posting webhook!")
    except Exception as e: log.error(f"디코 웹훅 전송 실패! | {e}")
    return sc