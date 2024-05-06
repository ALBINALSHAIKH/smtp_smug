import os, sys, ast
import argparse
import asyncio
import socket

file_path = 'aiosmtpd/'
sys.path.append(os.path.dirname(file_path))
import aiosmtpd.smtp
from aiosmtpd.controller import Controller

from smtplib import SMTP as client_SMTP

#IP dictionary
smtp_servers = {
  'SMTP1': ['192.168.122.1', 8025, ['\r\n']],
  'SMTP2': ['192.168.122.2', 8030, ['\r\n', '\t']],
  'SMTP3': ['192.168.122.3', 8035, ['\t']],
}


class CustomHandler:
  def relay_email(self, hostname, mail_from, rcpt, data):
    dest = smtp_servers[rcpt[rcpt.index('@') + 1 : ]]
    # print("Relaying email to {} at {}:{}".format(rcpt[rcpt.index('@') + 1 : ], dest[0], dest[1]))
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.connect((dest[0], dest[1]))

    #Send the email and ensure to include the compatible DATA seperator!
    cli.sendall(b'')
    msg = 'HELO {}\r\n'.format(hostname)
    cli.sendall(msg.encode())
    recv = cli.recv(8192)
    msg = 'MAIL FROM:{}\r\n'.format(mail_from)
    cli.sendall(msg.encode())
    recv = cli.recv(8192)
    msg = 'RCPT TO:{}\r\n'.format(rcpt)
    cli.sendall(msg.encode())
    recv = cli.recv(8192)
    msg = 'DATA\r\n'
    cli.sendall(msg.encode())
    recv = cli.recv(8192)
    msg = data.decode()
    msg = '{}{}.{}'.format(msg[:len(msg)-1], dest[2][0], dest[2][0])
    cli.sendall(msg.encode())
    recv = cli.recv(8192)

    cli.close()
    # print("Relayed!")
  
  def print_message(self, mail_from, rcpt, data):
    print("----Received Email----")
    print("FROM: {}\nTO: {}\nDATA: {}\n".format(mail_from, rcpt, data.decode()))
    print("----Email Ended----")

  async def handle_DATA(self, server, session, envelope):
    peer = session.peer
    mail_from = envelope.mail_from
    rcpt_tos = envelope.rcpt_tos
    data = envelope.content
    try:
      #Verify if recipient is this hostname or a different hostname
      for rcpt in rcpt_tos:
        if server.hostname == rcpt[rcpt.index('@') + 1 : ]:
          
          #Email received to this server! Printing!
          self.print_message(mail_from, rcpt, data)
        else:
          #Email should be relayed!
          #Recipient has a different hostname, then verify if sender is from here!
          if server.hostname == mail_from[mail_from.index('@') + 1 : ]:
            #Email will be relayed to the appropiate SMTP server.
            self.relay_email(server.hostname, mail_from, rcpt, data)
          else:
            return "500 Sender's mailbox does not exist! (Hostname mismatch)"
    except :
      return '500 Could not process your message'
    return '250 OK'
  
class CustomHostnameController(Controller):
  def __init__(self, *args, custom_hostname, **kwargs):
    super().__init__(*args, **kwargs)
    self.custom_hostname = custom_hostname

  def factory(self):
    return aiosmtpd.smtp.SMTP(self.handler, hostname=self.custom_hostname)


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('ip', metavar='IP', type=str,
                    help='IP address of server')
  parser.add_argument('port', metavar='PORT', type=int,
                    help='Port of the server')
  parser.add_argument('hostname', metavar='HOSTNAME', type=str,
                    help='Hostname of the server')
  parser.add_argument('-d','--delimiters', metavar='DELIMITERS', required=True, nargs='+', type=str,
                    help='Delimiters of the server')
  parser.add_argument('-s','--servers', metavar='SERVERS', required=True, nargs='+', type=str,
                    help='IP addresses of the SMTP servers in the format IP:PORT')
  
  args = parser.parse_args()
  addr = args.ip
  port = args.port
  custom_hostname = args.hostname
  delimiters = []
  for x in args.delimiters:
    delimiters.append(ast.literal_eval(f'"{x}"').encode())
  servers = []
  for x in args.servers:
    try:
      temp_addr = x[:x.index(':')]
      temp_port = int(x[x.index(':') + 1 :])
      socket.inet_aton(temp_addr)  
      servers.append([temp_addr, temp_port]) 
    except:
      print("SMTP IP address {} is not valid!".format(x))
      exit()
  try:
     socket.inet_aton(addr)
  except socket.error:
    print("IP address is not valid!")
    exit()

  #Modify the limiters for the "DATA" command
  aiosmtpd.smtp.DATA_LIMITER = tuple(delimiters)

  #Update the smtp server table
  smtp_servers['SMTP1'] = [servers[0][0], servers[0][1], smtp_servers['SMTP1'][2]]
  smtp_servers['SMTP2'] = [servers[1][0], servers[1][1], smtp_servers['SMTP2'][2]]
  smtp_servers['SMTP3'] = [servers[2][0], servers[2][1], smtp_servers['SMTP3'][2]]

  controller = CustomHostnameController(CustomHandler(),
                                        hostname=addr,
                                        port=port,
                                        custom_hostname=custom_hostname)

  # Run the event loop in a separate thread.
  controller.start()
  # Wait for the user to press Return.
  input('SMTP server running. Press Return to stop server and exit.\n')
  controller.stop()
