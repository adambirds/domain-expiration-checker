import smtplib
import zulip
from pyzabbix import ZabbixSender, ZabbixMetric
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from .helper import debug


def send_expire_email(domain, days, config_options):
    """
       Generate an e-mail to let someone know a domain is about to expire
    """
    debug("Generating an e-mail to %s for domain %s" %
         (config_options['APP']['SMTP_SEND_TO'], domain), config_options)
    msg = MIMEMultipart()
    msg['From'] = config_options['APP']['SMTP_FROM']
    msg['To'] = config_options['APP']['SMTP_SEND_TO']
    msg['Subject'] = "The DNS Domain %s is set to expire in %d days" % (domain, days)

    body = "The DNS Domain %s is set to expire in %d days" % (domain, days)
    msg.attach(MIMEText(body, 'plain'))

    smtp_connection = smtplib.SMTP(config_options['APP']['SMTP_SERVER'],config_options['APP']['SMTP_PORT'])
    message = msg.as_string()
    smtp_connection.sendmail(config_options['APP']['SMTP_FROM'], config_options['APP']['SMTP_SEND_TO'], message)
    smtp_connection.quit()

def send_expire_zulip_message(domain, days, config_options):
    

    # Pass the path to your zuliprc file here.
    client = zulip.Client(config_file=config_options['APP']['ZULIP_BOT_FILE'])

    # Send a stream message
    request = {
        "type": "stream",
        "to": config_options['APP']['ZULIP_STREAM'],
        "topic": domain,
        "content": "The domain %s is set to expire in %d days. Please check with customer if they wish to renew." % (domain, days)
    }
    result = client.send_message(request)

def send_completion_zulip_message(config_options):
    

    # Pass the path to your zuliprc file here.
    client = zulip.Client(config_file=config_options['APP']['ZULIP_BOT_FILE'])

    # Send a stream message
    request = {
        "type": "stream",
        "to": config_options['APP']['ZULIP_STREAM'],
        "topic": "Domain Check Complete",
        "content": "All domains have been successfully checked for expiry." 
    }
    result = client.send_message(request)

def send_error_zulip_message(error, config_options):
    

    # Pass the path to your zuliprc file here.
    client = zulip.Client(config_file=config_options['APP']['ZULIP_BOT_FILE'])

    # Send a stream message
    request = {
        "type": "stream",
        "to": config_options['APP']['ZULIP_ERROR_STREAM'],
        "topic": "Domain Check Error",
        "content": error 
    }
    result = client.send_message(request)

def send_zabbix_script_monitoring(status_code, config_options):
    metrics = []
    m = ZabbixMetric(config_options['APP']['SERVER_NAME'], "cron.domain_expiry_checker", status_code)
    metrics.append(m)
    zbx = ZabbixSender(use_config=config_options['APP']['ZABBIX_CONFIG_FILE'])
    zbx.send(metrics)