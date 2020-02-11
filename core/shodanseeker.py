import textwrap
import argparse
import datetime
import logging
from optparse import OptionParser
import os
import smtplib
import sys
import time
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication

# migrated to py3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import click
import coloredlogs
import requests
from ipcalc import Network
from shodan import Shodan
from shodan.exception import APIError
from shodan.helpers import get_ip

# Create a logger object para poder logar los errores que nos aparezcan esto para el bot
logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG')
logging.basicConfig(filename='logs/seeker.log', filemode='w', level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fecha = datetime.now()
filereportname = fecha.strftime("%Y-%m-%d-%H%M%S")


class ShodanSeeker:
    def __init__(self, config, api_key=None, proxies=None):
        self.api_key = api_key
        self.proxies = proxies
        self.api = Shodan(self.api_key, self.proxies)
        self.force = False
        self.config = config

    def log(self, action="", data=""):
        if action == "Error":
            logging.error('[Error] ' + fecha.strftime("%c") + ' - ' + str(data))
        elif action == "newline":
            msg = "\n"
        else:
            logging.info('[ Log ] ' + fecha.strftime("%c") + ' - ' + str(action) + str(data))
        filelogname = fecha.strftime("%m-%Y")
        for logpath in self.config.paths:
            # noinspection PyAttributeOutsideInit
            self.logpath = self.config.paths['logpath']
        filelogpath = str(self.logpath) + filelogname + ".log"
        if os.path.isfile(filelogpath):
            fich = open(filelogpath, "a")
            fich.write(msg + '\n')
            fich.close()
        else:
            fich = open(filelogpath, "w")
            fich.write(msg + '\n')
            fich.close()
        if action != "newline":
            logging.info(str(msg))  # Console output

    def add_scanid(self, id):
        for scanidpath in self.config.paths:
            # noinspection PyAttributeOutsideInit
            self.scanidpath = self.config.paths['scanidpath'] + "scanID.txt"
        if os.path.isfile(self.scanidpath):
            fich = open(self.scanidpath, "a")
            fich.write(id + '\t' + fecha.strftime("%c") + '\n')
            fich.close()
        else:
            fich = open(self.scanidpath, "w")
            fich.write('    Scan ID              Date      \n')
            fich.write(id + '\t' + fecha.strftime("%c") + '\n')
            fich.close()

    def print_scanlistID(self):
        for scanidpath in self.config.paths:
            self.scanidpath = self.config.paths['scanidpath'] + "scanID.txt"
        if os.path.isfile(self.scanidpath):
            try:
                with open(self.scanidpath, "r") as file_lines:
                    for line in file_lines:
                        print(line)
                        """Meter el send message de telegram
                        context.bot.send_message(chat_id=update.effective_chat.id,
                         text=line r"""
            except APIError as e:
                logging.error("Error:", e)
                sys.exit(1)
        else:
            """print('No scan has been sent yet')
            Cambiarr por el send message de telegram"""
            logging.info("[SCANLIST] No scan has been sent yet")
            sys.exit(1)

    def scan_range(self, input, force):
        logging.info("Scan IP/netblock - ", input)
        list = input.split(" ")
        dictips = dict.fromkeys(list, [])
        # self.log("List of IPs - ", list)
        try:
            logging.info("Force status - ", str(force))
            scan = self.api.scan(dictips, force)
            id = scan["id"]
            logging.info("Scan ID: ", id)
            self.add_scanid(id)
            logging.info("Check results on : https://www.shodan.io/search?query=scan%3A" + id)
            logging.info("newline")
        except APIError as e:
            logging.info("Error", e)
            logging.info("newline")
            sys.exit(1)

    def scan_file(self, file, force):
        logging.info("Scan file - ", file)
        try:
            with open(file, "r") as file_lines:
                lista = []
                for line in file_lines:
                    lista.append(line.replace('\n', ''))
                try:
                    dictips = dict.fromkeys(lista, [])
                    self.log("List of IPs - ", lista)
                    self.log("Force status - ", str(force))
                    scan = self.api.scan(dictips, force)
                    time.sleep(0.5)
                    id = scan["id"]
                    self.log("Scan ID: ", id)
                    self.add_scanid(id)
                    self.log("Check results on : https://www.shodan.io/search?query=scan%3A" + id)
                    self.log("newline")
                except APIError as e:
                    self.log("Error", e.value)
                    self.log("newline")
                    sys.exit(1)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def get_info(self, input, history, diff, output, toaddr, attach):
        self.log("Get info from IP/netblock - ", input)
        # self.log("History banners - ", history)
        # self.log("Diff - ", diff)
        # self.log("Format - ", output)
        if toaddr is not None:
            try:
                self.log("Mail - ", self.config.mail[toaddr])
            except KeyError as e:
                e = "Address is not found in config.py: " + toaddr
                self.log("Error", e)
                self.log("newline")
                sys.exit(1)
        # else:
        # self.log("Mail - ", toaddr)
        res = ""
        res1 = ""
        lista = input.split(" ")
        # self.log("List Split - ", list)
        for reportpath in self.config.paths:
            self.reportpath = self.config.paths['reportpath']
        if history is not None:
            if diff is not None:
                filereportpath = str(self.reportpath) + str('diffing/') + filereportname + ".csv"
            else:
                filereportpath = str(self.reportpath) + str('history/') + filereportname + ".csv"
        else:
            filereportpath = str(self.reportpath) + filereportname + ".csv"
        for item in lista:
            if "/" not in item:
                try:
                    host = self.api.host(item, history)
                    resaux = self.host_print(host, history, output, filereportpath, diff, toaddr)
                    res = str(res) + '\n' + str(resaux)  # body mail
                except APIError as e:
                    self.log("Error", e.value)
                    self.log("newline")
                    pass
            else:
                for x in Network(item):
                    try:
                        host = self.api.host(str(x), history)
                        time.sleep(0.5)
                        resaux = self.host_print(host, history, output, filereportpath, diff, toaddr)
                        res = str(res) + '\n' + str(resaux)  # body mail
                    except APIError as e:
                        self.log("Error", e.value)
                        self.log("newline")
                        time.sleep(0.5)
                        pass
        if (output) is not None:
            self.log("Report: ", filereportpath)
            self.log("newline")
            res1 = "Results on " + filereportpath
        if (toaddr) is not None:
            body = res1 + "\n" + res
            subject = "[Searching results]"
            if (diff):
                subject = subject + " New services published"
            else:
                if (history):
                    subject = subject + " All historical banners"
                else:
                    subject = subject + " All services"
            self.send_mail(subject, body, toaddr, attach, filereportpath)

    def get_infofromfile(self, file, history, diff, output, toaddr, attach):
        self.log("Get info from file - ", file)
        # self.log("History banners - ", history)
        # self.log("Diff - ", diff)
        # self.log("Format - ", output)
        if (toaddr) is not None:
            try:
                self.log("Mail - ", self.config.mail[toaddr])
            except KeyError as e:
                e = "Address is not found in config.py: " + toaddr
                self.log("Error", e)
                self.log("newline")
                sys.exit(1)
        # else:
        # self.log("Mail - ", toaddr)
        res = ""  # body mail
        res1 = ""
        try:
            with open(file, "r") as file_lines:
                lista = []
                for line in file_lines:
                    lista.append(line.replace('\n', ''))
                self.log("List of IPs/netblock - ", lista)
                for reportpath in self.config.paths:
                    self.reportpath = self.config.paths['reportpath']
                if (history) is not None:
                    if (diff) is not None:
                        filereportpath = str(self.reportpath) + str('diffing/') + filereportname + ".csv"
                    else:
                        filereportpath = str(self.reportpath) + str('history/') + filereportname + ".csv"
                else:
                    filereportpath = str(self.reportpath) + filereportname + ".csv"
                for item in list:
                    if "/" not in item:
                        try:
                            host = self.api.host(item, history)
                            time.sleep(0.5)
                            resaux = self.host_print(host, history, output, filereportpath, diff, toaddr)
                            res = str(res) + '\n' + str(resaux)  # body mail
                        except APIError as e:
                            self.log("Error", e.value)
                            self.log("newline")
                            pass
                    else:
                        for x in Network(item):
                            try:
                                host = self.api.host(str(x), history)
                                time.sleep(0.5)
                                resaux = self.host_print(host, history, output, filereportpath, diff, toaddr)
                                res = str(res) + '\n' + str(resaux)  # body mail
                            except APIError as e:
                                self.log("Error", e.value)
                                self.log("newline")
                                time.sleep(0.5)
                                pass
                if (output) is not None:
                    self.log("Report: ", filereportpath)
                    self.log("newline")
                    res1 = "Results on " + filereportpath
                if (toaddr) is not None:
                    body = res1 + "\n" + res
                    subject = "[Searching results]"
                    if (diff):
                        subject = subject + " New services published"
                    else:
                        if (history):
                            subject = subject + " All historical banners"
                        else:
                            subject = subject + " All services"
                    self.send_mail(subject, body, toaddr, attach, filereportpath)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def host_print(self, host, history, output, filereportpath, diff, toaddr):
        self.res = ""
        if None == output:
            self.host_gethistdiff(host, history, None, filereportpath, diff, toaddr, None)
        else:
            if output == 'csv':
                self.res = self.host_gethistdiff(host, history, output, filereportpath, diff, toaddr, None)
            else:
                print('[Error] Output format not supported')
                sys.exit(1)
        return self.res

    def host_gethistdiff(self, host, history, output, filereportpath, diff, toaddr, subs):
        """

        @rtype: object
        """
        self.file = None
        self.hostname = None
        self.os = None
        self.lastupdate = None
        self.ports = []
        self.product = None
        self.version = None
        self.transport = None
        self.timestamp = None
        self.res = ""

        if output is not None:
            if os.path.isfile(filereportpath):
                self.file = open(filereportpath, "a")
            else:
                self.file = open(filereportpath, "w")
                data = 'Hostname,OS,LastUpdate,Port,Transport,Product,Version,Timestamp'
                self.file.write(data + '\n')

        self.hostname = get_ip(host)
        if 'os' in host and host['os']:
            self.os = host['os']
        if 'last_update' in host and host['last_update']:
            self.lastupdate = host['last_update'][:10]

        if output is None and subs is None:
            resaux = '\n' + 'Hostname: ' + str(self.hostname)
            if toaddr is None:
                print(resaux)
            else:
                self.res = self.res + str(resaux) + '\n'
            if self.os:
                resaux = 'OS: ' + str(self.os)
                if toaddr is None:
                    print(resaux)
                else:
                    self.res = self.res + str(resaux) + '\n'
            resaux = 'LastUpdate: ' + str(self.lastupdate) + '\n'
            if toaddr is None:
                print(resaux)
            else:
                self.res = self.res + str(resaux)

        if len(host['ports']) != len(host['data']):
            ports = host['ports']
            for banner in host['data']:
                if banner['port'] in ports:
                    ports.remove(banner['port'])

            for port in ports:
                banner = {
                    'port': port,
                    'transport': 'tcp',
                    'timestamp': host['data'][-1]['timestamp']
                }
                host['data'].append(banner)

        if diff is None:  # Regular and History option
            for banner in sorted(host['data'], key=lambda k: k['port']):
                self.product = None
                self.version = None
                self.transport = None
                self.timestamp = None

                if 'product' in banner and banner['product']:
                    self.product = banner['product']

                if 'version' in banner and banner['version']:
                    self.version = '({})'.format(banner['version'])

                if 'transport' in banner:
                    self.transport = banner['transport']

                if history:
                    # Format the timestamp to only show the year-month-day
                    self.timestamp = banner['timestamp'][:10]

                if output is None:
                    resaux = self.host_printoutput(banner['port'], self.transport, self.product, self.version,
                                                   self.timestamp, toaddr, subs)
                    self.res = self.res + resaux
                else:
                    data = str(self.hostname) + ',' + str(self.os) + ',' + str(self.lastupdate)
                    data = data + ',' + str(banner['port']) + ',' + str(self.transport)
                    data = data + ',' + str(self.product) + ',' + str(self.version) + ',' + str(self.timestamp)
                    self.file.write(data + '\n')

        if diff:  # Diffing option

            self.ports_uniq = host['ports']

            if len(self.ports_uniq) < 1:
                for banner in host['data']:
                    if banner['port'] not in self.ports_uniq:
                        self.ports_uniq.append(banner['port'])

            # list_timestamps_uniq_sort_host
            self.listtimestamp = []
            for banner in host['data']:
                timestamp = banner['timestamp'][:10]
                if timestamp and timestamp not in self.listtimestamp:
                    self.listtimestamp.append(timestamp)

            # list_timestamp_host_port
            for port in self.ports_uniq:
                self.listbannerport = []
                self.listporttimestamps = []
                for banner in sorted(host['data'], key=lambda k: k['port']):
                    if port == banner['port']:
                        timestampport = banner['timestamp'][:10]
                        if timestampport and timestampport not in self.listporttimestamps:
                            self.listporttimestamps.append(timestampport)
                            self.listbannerport.append(banner)

                for bannerport in self.listbannerport:
                    self.timestamp = bannerport['timestamp'][:10]
                    self.port = bannerport['port']
                    if 'product' in bannerport and bannerport['product']:
                        self.product = bannerport['product']
                    if 'version' in bannerport and bannerport['version']:
                        self.version = '({})'.format(bannerport['version'])
                    if 'transport' in bannerport:
                        self.transport = (bannerport['transport'])
                    next_timestamp_port = None
                    next_timestamp_host = None

                    if self.lastupdate is self.timestamp:
                        date = datetime.now()
                        timestamp = datetime.strptime(self.lastupdate, '%Y-%m-%d')
                        timestamp_ajust = timestamp + timedelta(days=32)
                        if date <= timestamp_ajust:
                            if len(self.listbannerport) == 1:
                                if output is None:
                                    resaux = self.host_printoutput(self.port, self.transport, self.product,
                                                                   self.version, self.timestamp, toaddr, subs)
                                    self.res = self.res + resaux
                                else:
                                    data = str(self.hostname) + ',' + str(self.os) + ',' + str(self.lastupdate)
                                    data = data + ',' + str(self.port) + ',' + str(self.transport)
                                    data = data + ',' + str(self.product) + ',' + str(self.version) + ',' + str(
                                        self.timestamp)
                                    self.file.write(data + '\n')
                            else:
                                next_timestamp_port = self.listbannerport[1]['timestamp'][:10]
                                next_timestamp_host = self.listtimestamp[1]
                                if next_timestamp_port != next_timestamp_host:
                                    if output is None:
                                        resaux = self.host_printoutput(self.port, self.transport, self.product,
                                                                       self.version, self.timestamp, toaddr, subs)
                                        self.res = self.res + resaux
                                    else:
                                        data = str(self.hostname) + ',' + str(self.os) + ',' + str(self.lastupdate)
                                        data = data + ',' + str(self.port) + ',' + str(self.transport)
                                        data = data + ',' + str(self.product) + ',' + str(self.version) + ',' + str(
                                            self.timestamp)
                                        self.file.write(data + '\n')
        if output:
            self.file.close()
        return self.res

    # TODO: implementar la funcionalidad de envio
    def send_mail(self, subject, body, toaddr, attached, filepath):
        self.fromaddress = self.config.mail['fromaddress']
        self.frompassword = self.config.mail['frompassword']
        self.toaddress = self.config.mail[toaddr]
        self.smtp = self.config.mail['smtp']
        msg = msg = MIMEMultipart()
        msg['From'] = str(self.fromaddress)
        msg['To'] = str(self.toaddress)
        msg['Subject'] = str(subject)
        body = str(body)
        msg.attach(MIMEText(body, 'plain'))
        if attached:
            part = MIMEApplication(open(filepath, 'rb').read())
            part['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(filepath)
            msg.attach(part)
        server = smtplib.SMTP(self.smtp, 587)
        try:
            # TODO Remove self log and replace them with logger
            server.starttls()
            server.login(self.fromaddress, self.frompassword)
            text = msg.as_string()
            server.sendmail(self.fromaddress, self.toaddress, text)
            server.quit()
            self.log("Mail sent: ", subject)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def create_alert(self, name, ips):
        self.log("Create alert")
        self.log("IPs/netblock - ", ips)
        lista = ips.split(" ")
        self.log("List of IPs - ", lista)
        try:
            i = 0
            for ip in lista:
                namenew = name + '_' + str(i)
                alert = self.api.create_alert(name, ip)
                time.sleep(0.5)
                id = alert["id"]
                self.log("Alert Name: ", namenew)
                self.log("Alert ID: ", id)
                self.log("newline")
                i = i + 1
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    # TODO añadir logger
    def create_alertfile(self, name, file):
        self.log("Create alert")
        self.log("File of ips ", file)
        try:
            with open(file, "r") as file_lines:
                lista = []
                i = 0
                for line in file_lines:
                    lista.append(line.replace('\n', ''))
                try:
                    self.log("List of IPs - ", lista)
                    for ip in lista:
                        namenew = name + '_' + str(i)
                        alert = self.api.create_alert(namenew, ip)
                        time.sleep(0.5)
                        id = alert["id"]
                        self.log("Alert Name: ", namenew)
                        self.log("Alert ID: ", id)
                        self.log("newline")
                        i = i + 1
                except APIError as e:
                    self.log("Error", e.value)
                    self.log("newline")
                    sys.exit(1)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def list_alerts(self):
        try:
            results = self.api.alerts()
        except APIError as e:
            print('[Error]' + e.value)
            sys.exit(1)

        if len(results) > 0:
            click.echo(click.style('{0:<30}'.format('AlertID')) + click.style(
                '{0:<30}'.format('Name') + 'IP/Netblock') + '\n')
            for alert in results:
                click.echo(click.style('{0:<30}'.format(alert['id'])) + click.style(
                    '{0:<30}'.format(alert['name']) + str(alert['filters']['ip'][0])))
        else:
            print('You have not created any alerts yet')

    def delete_alert(self, alertid):
        if str(alertid) == "all":
            self.remove_allalerts()
        else:
            try:
                self.api.delete_alert(alertid)
                self.log("Alert ID removed: ", alertid)
                self.log("newline")
            except APIError as e:
                self.log("Error", e.value)
                self.log("newline")
                sys.exit(1)

    def remove_allalerts(self):
        try:
            alerts = self.api.alerts()
            time.sleep(0.5)
            for alert in alerts:
                self.log("Removing alert: " + alert['name'] + " - " + alert['id'])
                self.api.delete_alert(alert['id'])
                time.sleep(0.5)
            self.log("All alerts have been removed")
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def subscribe_ports(self, alertid, monport, toaddr):
        self.alertid = alertid
        self.monport = monport
        self.toaddr = toaddr
        try:
            monitemlist = monport.split(" ")
            self.api.stream.base_url = "https://stream.shodan.io"
            if str(alertid) == "all":
                self.alertid = None
            else:
                self.alertid = alertid
            for banner in self.api.stream.alert(self.alertid):
                for m in monitemlist:
                    if str((banner['port'])) == str(m):
                        ip = str(get_ip(banner))
                        port = str((banner['port']))
                        data = 'Hostname: ' + ip + ' Port: ' + port
                        self.log('Alert: ', data)
                        if (toaddr) is not None:
                            self.send_mail('[Alert] Risk port open', data, toaddr, None, None)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)
        except requests.exceptions.ChunkedEncodingError:
            self.subscribe_ports(self.alertid, self.monport, self.toaddr)

    def subscribe_diff(self, alertid, toaddr):
        self.alertid = alertid
        self.toaddr = toaddr
        try:
            self.api.stream.base_url = "https://stream.shodan.io"
            if str(alertid) == "all":
                self.alertid = None
            else:
                self.alertid = alertid
            for banner in self.api.stream.alert(self.alertid):
                ip_stream = str(get_ip(banner))
                port_stream = str((banner['port']))
                # print "IP " + str(ip_stream)
                # print "port_stream " + str(port_stream)
                banner = self.api.host(ip_stream, True)
                time.sleep(0.5)
                res = self.host_gethistdiff(banner, True, None, None, True, None, True)
                res = res.split(' ')
                # print "RES " + str(res)
                if port_stream in res:
                    data = 'Hostname: ' + ip_stream + ' Port: ' + port_stream
                    self.log('Alert : ', data)
                    if (toaddr) is not None:
                        self.send_mail('[Alert] New service detected', data, toaddr, None, None)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)
        except requests.exceptions.ChunkedEncodingError:
            self.subscribe_diff(self.alertid, self.toaddr)

    def subscribe_tags(self, alertid, montags, toaddr):
        self.alertid = alertid
        self.montags = montags
        self.toaddr = toaddr
        try:
            monitemlist = montags.split(" ")
            self.api.stream.base_url = "https://stream.shodan.io"
            if str(alertid) == "all":
                self.alertid = None
            else:
                self.alertid = alertid
            for banner in self.api.stream.alert(self.alertid):
                for m in monitemlist:
                    if 'tags' in banner and str(m) in banner['tags']:
                        ip = str(get_ip(banner))
                        data = 'Hostname: ' + ip + ' Tag: ' + str(m)
                        self.log('Alert: ', data)
                        if (toaddr) is not None:
                            self.send_mail('[Alert] Tag detected', data, toaddr, None, None)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)
        except requests.exceptions.ChunkedEncodingError:
            self.subscribe_tags(self.alertid, self.montags, self.toaddr)

    def get_services(self, input):
        if str(input) == "services":
            res = self.api.services()
            for name, description in iter(res.items()):
                click.echo(click.style('{0:<30}'.format(name)) + description)
        elif str(input) == "protocols":
            res = self.api.protocols()
            for name, description in iter(res.items()):
                click.echo(click.style('{0:<30}'.format(name)) + description)
        elif str(input) == "ports":
            res = self.api.protocols()
            for name, description in iter(res.items()):
                click.echo(click.style('{0:<30}'.format(name)) + description)
        elif str(input) == "tags":
            for mainpath in self.config.paths:
                mainpath = self.config.paths['mainpath'] + "tags"
            if os.path.isfile(mainpath):
                try:
                    with open(mainpath, "r") as file_lines:
                        for line in file_lines:
                            print
                            line.rstrip('\n')
                except APIError as e:
                    self.log("Error", e.value)
                    sys.exit(1)
            else:
                print('No scan has been sent yet')
                sys.exit(1)
        else:
            print("[Error] - Input must be: protocols, services or ports")
            sys.exit(1)

    @property
    def run(self):

        parser = argparse.ArgumentParser(prog='shodanseeker.py', usage="usage: pythOn %(prog)s [options]",
                                         description="Command line tool for diffing scanning results, monitor, and set alets on a given asset or range.",
                                         formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent('''\

EXAMPLES:
  ./shodanseeker --si 'X.X.X.X X.X.X.X/24'                                   # Scan IPs/netblocks
  ./shodanseeker --sf 'pathfilename'                                         # Scan IPs/netblocks from a file
  ./shodanseeker -l                                                          # List previously submitted scans
  ./shodanseeker -i 'X.X.X.X X.X.X.X/24 Y.Y.Y.Y'                             # Get all information of IP/netblocks
  ./shodanseeker -f 'pathfilename'                                           # Get all information from a file of IPs/netblocks
  ./shodanseeker -i 'X.X.X.X' --history                                      # Get all historical banners
  ./shodanseeker -i 'X.X.X.X' --diff                                         # Detect new services published
  ./shodanseeker -f 'pathfilename' [--history|--diff] --output csv           # Output results in csv format
  ./shodanseeker -i 'X.X.X.X' --diff --output csv --mail toaddr -a           # Send email with csv results attached
  ./shodanseeker --ca Name 'X.X.X.X X.X.X.X/24'                              # Create network alerts for the IP/netblock
  ./shodanseeker --cf Name 'pathfilename'                                    # Create network alerts from file
  ./shodanseeker --la                                                        # List of all the network alerts activated on the account
  ./shodanseeker --da [alertid|all]                                          # Remove the specified network alert
  ./shodanseeker --subs [alertid|all] --monport '3389 22' [--mail toaddr]    # Subscribe to the Streaming and monitoring for high risk services
  ./shodanseeker --subs [alertid|all] --mondiff [--mail toaddr]              # Subscribe to the Streaming and monitoring for new services published
  ./shodanseeker --subs [alertid|all] --montag 'compromised' [--mail toaddr] # Subscribe to the Streaming and monitoring for tags (ex: compromised, doublepulsar, self-signed)
  ./shodanseeker --get [protocols|services|ports|tags]                       # List of (protocols,services,ports,tags) supported
        '''))

        #parser.add_argument('-h', '--help', action=help)
        parser.add_argument("--mail", dest="mail", help="Send email with results and alerts", default=None)
        parser.add_argument("-a", dest="attach", action="store_true", help="Attach csv results to an email",
                            default=None)

        group1 = parser.add_argument_group('Scanning options')
        group1.add_argument('--si', dest='scaninput', help='Scan an IP/netblock', default=None)
        group1.add_argument('--sf', dest='scanfile', help='Scan an IP/netblock from file', default=None)
        group1.add_argument('--force', dest="scanforce", help="Force Shodan to re-scan the provided IPs",
                            action="store_true", default=None)
        group1.add_argument("-l", dest="scanlist", action="store_true", help="List previously submitted scans",
                            default=None)
        parser.add_argument_group(group1)

        group2 = parser.add_argument_group('Searching Options')
        group2.add_argument('-i', dest="getinfo", help="Get all information of an IP/netblock", default=None)
        group2.add_argument("-f", dest="getinfofromfile",
                            help="Get all information of an IP/netblock from file",
                            default=None)
        group2.add_argument("--history", dest="history", help="Return all Historical Banners",
                            action="store_true",
                            default=None)
        group2.add_argument("--diff", dest="diff", help="Detect New Services Published", action="store_true",
                            default=None)
        group2.add_argument("--output", dest="output", help="Output results in csv format", default=None)
        parser.add_argument_group(group2)

        group3 = parser.add_argument_group('Monitoring in Real-Time')
        group3.add_argument("--ca", dest="addalert", help="Create network alerts for the IP/netblock", nargs=2,
                            default=None)
        group3.add_argument("--cf", dest="addalertfile", help="Create network alerts from file", nargs=2,
                            default=None)
        group3.add_argument("--la", dest="listalerts", help="List of all the network alerts activated",
                            action="store_true", default=None)
        group3.add_argument("--da", dest="delalert", help="Remove the specified network alert", default=None)
        group3.add_argument("--subs", dest="subsalerts", help="Subscribe to the Private Horse Streaming",
                            default=None)
        group3.add_argument("--monport", dest="monport", help="Monitoring for High Risk Services", default=None)
        group3.add_argument("--mondiff", dest="mondiff", action="store_true",
                            help="Monitoring for New Services Published", default=None)
        group3.add_argument("--montag", dest="montag", help="Tags (ex: compromised, doublepulsar, self-signed)",
                            default=None)
        group3.add_argument("--get", dest="get", help="Protocols, services, ports and tags supported",
                            default=None)
        parser.add_argument_group(group3)

        myoption = parser.parse_args()

        # for key in self.config.api:
        #     self.api_key = key['key']
        # for logpath in self.config.paths:
        #     # TODO:
        #     self.logpath = self.config.paths['logpath']

        for key in self.config.api:
            self.api_key = key['key']
        for logpath in self.config.paths:
            self.logpath = self.config.paths['logpath']

        if self.api_key == '':
            print('[Error] Set the Shodan API Key into the configuration file')
            logger.error('[Error NO API] Set the Shodan API Key into the configuration file')
            sys.exit(1)

        if myoption.scaninput:
            if myoption.scaninput:
                if myoption.scanforce:
                    self.force = True
                shodanscan = ShodanSeeker(self.api_key)
                shodanscan.scan_range(myoption.scaninput, self.force)
            else:
                print('[Error] Input must not be null')
                sys.exit(1)

        elif myoption.scanfile:
            if myoption.scanfile:
                if os.path.isfile(myoption.scanfile):
                    if myoption.scanforce:
                        self.force = True
                    shodanscan = ShodanSeeker(self.api_key)
                    shodanscan.scan_file(myoption.scanfile, self.force)
                else:
                    print('[Error] File does not exist')
                    sys.exit(1)
            else:
                print('[Error] Input must not be null')
                sys.exit(1)

        elif myoption.scanlist:
            self.print_scanlistID()

        elif myoption.getinfo:
            if myoption.getinfo:
                shodangetinfo = ShodanSeeker(self.api_key)
                if myoption.history and myoption.diff:
                    parser.error("Options --history and --diff are mutually exclusive")
                if myoption.history:
                    if myoption.output:
                        if myoption.output == 'csv':
                            if myoption.mail:
                                if myoption.mail in self.config.mail:
                                    if myoption.attach:
                                        shodangetinfo.get_info(myoption.getinfo, myoption.history, None,
                                                               myoption.output,
                                                               myoption.mail, myoption.attach)
                                    else:
                                        shodangetinfo.get_info(myoption.getinfo, myoption.history, None,
                                                               myoption.output,
                                                               myoption.mail, None)
                                else:
                                    print('[Error] Select a valid toaddress list from config file')
                            else:
                                shodangetinfo.get_info(myoption.getinfo, myoption.history, None, myoption.output, None,
                                                       None)
                        else:
                            print('[Error] Output format not supported')
                    else:
                        if myoption.mail:
                            if myoption.attach:
                                print('[Error] Select a file format output')
                            else:
                                shodangetinfo.get_info(myoption.getinfo, myoption.history, None, None, myoption.mail,
                                                       None)
                        else:
                            shodangetinfo.get_info(myoption.getinfo, myoption.history, None, None, None, None)
                else:
                    if myoption.diff:
                        if myoption.output:
                            if myoption.output == 'csv':
                                if myoption.mail:
                                    if myoption.mail in self.config.mail:
                                        if myoption.attach:
                                            shodangetinfo.get_info(myoption.getinfo, True, myoption.diff,
                                                                   myoption.output,
                                                                   myoption.mail, myoption.attach)
                                        else:
                                            shodangetinfo.get_info(myoption.getinfo, True, myoption.diff,
                                                                   myoption.output,
                                                                   myoption.mail, None)
                                    else:
                                        print('[Error] Select a valid toaddress list from config file')
                                else:
                                    shodangetinfo.get_info(myoption.getinfo, True, myoption.diff, myoption.output, None,
                                                           None)
                            else:
                                print('[Error] Output format not supported')
                        else:
                            if myoption.mail:
                                if myoption.mail in self.config.mail:
                                    if myoption.attach:
                                        print('[Error] Select a file format output')
                                    else:
                                        shodangetinfo.get_info(myoption.getinfo, True, myoption.diff, None,
                                                               myoption.mail,
                                                               None)
                                else:
                                    print('[Error] Select a valid toaddress list from config file')
                            else:
                                shodangetinfo.get_info(myoption.getinfo, True, myoption.diff, None, None, None)
                    else:
                        if myoption.output:
                            if myoption.output == 'csv':
                                if myoption.mail:
                                    if myoption.mail in self.config.mail:
                                        if myoption.attach:
                                            shodangetinfo.get_info(myoption.getinfo, None, None, myoption.output,
                                                                   myoption.mail, myoption.attach)
                                        else:
                                            shodangetinfo.get_info(myoption.getinfo, None, None, myoption.output,
                                                                   myoption.mail, None)
                                    else:
                                        print('[Error] Select a valid toaddress list from config file')
                                else:
                                    shodangetinfo.get_info(myoption.getinfo, None, None, myoption.output, None, None)
                            else:
                                print('[Error] Output format not supported')
                        else:
                            if myoption.mail:
                                if myoption.attach:
                                    print('[Error] Select a file format output')
                                else:
                                    shodangetinfo.get_info(myoption.getinfo, None, None, None, myoption.mail, None)
                            else:
                                shodangetinfo.get_info(myoption.getinfo, None, None, None, None, None)
            else:
                print('[Error] Input must not be null')
                sys.exit(1)

        elif myoption.getinfofromfile:
            if myoption.getinfofromfile:
                if os.path.isfile(myoption.getinfofromfile):
                    shodangetinfofromfile = ShodanSeeker(self.api_key)
                    if myoption.history and myoption.diff:
                        parser.error("Options --history and --diff are mutually exclusive")
                    if myoption.history:
                        if myoption.output:
                            if myoption.output == 'csv':
                                if myoption.mail:
                                    if myoption.mail in self.config.mail:
                                        if myoption.attach:
                                            shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile,
                                                                                   myoption.history, None,
                                                                                   myoption.output, myoption.mail,
                                                                                   myoption.attach)
                                        else:
                                            shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile,
                                                                                   myoption.history, None,
                                                                                   myoption.output, myoption.mail, None)
                                    else:
                                        print('[Error] Select a valid toaddress list from config file')
                                else:
                                    shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, myoption.history,
                                                                           None, myoption.output, None, None)
                            else:
                                print('[Error] Output format not supported')
                        else:
                            if myoption.mail:
                                if myoption.attach:
                                    print('[Error] Select a file format output')
                                else:
                                    shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, myoption.history,
                                                                           None, None, myoption.mail, None)
                            else:
                                shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, myoption.history, None,
                                                                       None, None, None)
                    else:
                        if myoption.diff:
                            if myoption.output:
                                if myoption.output == 'csv':
                                    if myoption.mail:
                                        if myoption.mail in self.config.mail:
                                            if myoption.attach:
                                                shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, True,
                                                                                       myoption.diff, myoption.output,
                                                                                       myoption.mail, myoption.attach)
                                            else:
                                                shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, True,
                                                                                       myoption.diff, myoption.output,
                                                                                       myoption.mail, None)
                                        else:
                                            # TODO config variable for print
                                            print('[Error] Select a valid toaddress list from config file')
                                    else:
                                        shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, True,
                                                                               myoption.diff, myoption.output, None,
                                                                               None)
                                else:
                                    print('[Error] Output format not supported')
                            else:
                                if myoption.mail:
                                    if myoption.mail in self.config.mail:
                                        if myoption.attach:
                                            print('[Error] Select a file format output')
                                        else:
                                            shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, True,
                                                                                   myoption.diff, None, myoption.mail,
                                                                                   None)
                                    else:
                                        print('[Error] Select a valid toaddress list from config file')
                                else:
                                    shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, True,
                                                                           myoption.diff,
                                                                           None, None, None)
                        else:
                            if myoption.output:
                                if myoption.output == 'csv':
                                    if myoption.mail:
                                        if myoption.mail in self.config.mail:
                                            if myoption.attach:
                                                shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, None,
                                                                                       None, myoption.output,
                                                                                       myoption.mail, myoption.attach)
                                            else:
                                                shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, None,
                                                                                       None, myoption.output,
                                                                                       myoption.mail, None)
                                        else:
                                            print('[Error] Select a valid toaddress list from config file')
                                    else:
                                        shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, None, None,
                                                                               myoption.output, None, None)
                                else:
                                    print('[Error] Output format not supported')
                            else:
                                if myoption.mail:
                                    if myoption.mail in self.config.mail:
                                        if myoption.attach:
                                            print('[Error] Select a file format output')
                                        else:
                                            shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, None, None,
                                                                                   None, myoption.mail, None)
                                    else:
                                        print('[Error] Select a valid toaddress list from config file')
                                else:
                                    shodangetinfofromfile.get_infofromfile(myoption.getinfofromfile, None, None, None,
                                                                           None, None)
                else:
                    print('[Error] File does not exist')
                    sys.exit(1)
            else:
                print('[Error] Input must not be null')
                sys.exit(1)

        elif myoption.addalert:
            if myoption.addalert:
                name = myoption.addalert[0]
                ips = myoption.addalert[1]
                shodanaddalert = ShodanSeeker(self.api_key)
                shodanaddalert.create_alert(name, ips)
            else:
                print('[Error] Input must not be null')
                sys.exit(1)

        elif myoption.addalertfile:
            if myoption.addalertfile:
                name = myoption.addalertfile[0]
                file = myoption.addalertfile[1]
                if os.path.isfile(file):
                    shodanaddalertfile = ShodanSeeker(self.api_key)
                    shodanaddalertfile.create_alertfile(name, file)
                else:
                    print('[Error] File does not exist')
                    sys.exit(1)
            else:
                print('[Error] Input must not be null')
                sys.exit(1)

        elif myoption.listalerts:
            shodanlistalerts = ShodanSeeker(self.api_key)
            shodanlistalerts.list_alerts()

        elif myoption.delalert:
            if myoption.delalert:
                shodanadddelalert = ShodanSeeker(self.api_key)
                shodanadddelalert.delete_alert(myoption.delalert)
            else:
                print('[Error] Input must not be null')
                sys.exit(1)

        elif myoption.subsalerts:
            if myoption.subsalerts:
                if myoption.monport:
                    shodansubs = ShodanSeeker(self.api_key)
                    if myoption.mail:
                        if myoption.mail in self.config.mail:
                            shodansubs.subscribe_ports(myoption.subsalerts, myoption.monport, myoption.mail)
                        else:
                            print('[Error] Select a valid toaddress list from config file')
                    else:
                        shodansubs.subscribe_ports(myoption.subsalerts, myoption.monport, None)
                elif myoption.mondiff:
                    shodansubs = ShodanSeeker(self.api_key)
                    if myoption.mail:
                        if myoption.mail in self.config.mail:
                            shodansubs.subscribe_diff(myoption.subsalerts, myoption.mail)
                        else:
                            print('[Error] Select a valid toaddress list from config file')
                    else:
                        shodansubs.subscribe_diff(myoption.subsalerts, None)
                elif myoption.montag:
                    shodansubs = ShodanSeeker(self.api_key)
                    if myoption.mail:
                        if myoption.mail in self.config.mail:
                            shodansubs.subscribe_tags(myoption.subsalerts, myoption.montag, myoption.mail)
                        else:
                            print('[Error] Select a valid toaddress list from config file')
                    else:
                        shodansubs.subscribe_tags(myoption.subsalerts, myoption.montag, None)
                else:
                    print('[Error] --mon option must not be null')
                    sys.exit(1)
            else:
                print('[Error] Input must not be null')
                sys.exit(1)

        elif myoption.get:
            if myoption.get:
                shodanget = ShodanSeeker(self.api_key)
                shodanget.get_services(myoption.get)
            else:
                print('[Error] Input must not be null')
                sys.exit(1)

        else:
            parser.print_help()
            print("")
            sys.exit(1)
